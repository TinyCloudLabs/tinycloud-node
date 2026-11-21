//! TC-3443: a retired (signed-out) session key invokes nothing and issues no
//! new delegation, while delegations it made before the retire, and their
//! descendants, keep working.
use super::*;
use crate::storage::memory::{MemoryStaging, MemoryStore};
use tinycloud_auth::{
    authorization::TinyCloudDelegation,
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

const TTL: time::Duration = time::Duration::days(30);

fn did_vm(key: &JWK) -> (String, String) {
    let did = DID_METHODS.generate(key, "key").unwrap().to_string();
    let vm = format!("{did}#{}", did.rsplit(':').next().unwrap());
    (did, vm)
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

struct Fx {
    db: Db,
    owner: JWK,
    session: JWK,
    holder: JWK,
    space: SpaceId,
    /// Expiries count back from here, so a child never outlives its parent.
    created: i64,
    _dir: Option<tempfile::TempDir>,
    _pg: Option<crate::test_support::PostgresTestSchema>,
}

impl Fx {
    fn session_did(&self) -> String {
        did_vm(&self.session).0
    }

    fn holder_did(&self) -> String {
        did_vm(&self.holder).0
    }

    fn kv(&self) -> String {
        self.space
            .clone()
            .to_resource(
                "kv".parse().unwrap(),
                Some("docs".parse().unwrap()),
                None,
                None,
            )
            .to_string()
    }

    /// A `kv/get` delegation from `issuer` to `audience`, citing `proof`.
    /// The owner's expire last, then the session key's, then the holder's.
    fn delegation(&self, issuer: &JWK, audience: &str, proof: Vec<Cid>) -> String {
        let mut caps = Capabilities::<serde_json::Value>::new();
        caps.with_action(
            self.kv().parse().unwrap(),
            "tinycloud.kv/get".parse().unwrap(),
            [std::collections::BTreeMap::new()],
        );
        Payload::<serde_json::Value> {
            issuer: did_vm(issuer).1.parse().unwrap(),
            audience: audience.parse().unwrap(),
            not_before: Some(NumericDate::try_from_seconds((now() - 60) as f64).unwrap()),
            expiration: NumericDate::try_from_seconds(self.expiry(issuer) as f64).unwrap(),
            nonce: Some(format!("tc3443-{}", rand::random::<u64>())),
            facts: None,
            proof,
            attenuation: caps,
        }
        .sign(Algorithm::EdDSA, issuer)
        .unwrap()
        .encode()
        .unwrap()
    }

    fn expiry(&self, issuer: &JWK) -> i64 {
        let depth = [&self.owner, &self.session, &self.holder]
            .iter()
            .position(|key| did_vm(key).0 == did_vm(issuer).0)
            .unwrap() as i64;
        self.created + 3600 - 900 * depth
    }

    /// `key` invokes `kv/get` on the fixture path under `proof`.
    async fn invoke(&self, key: &JWK, proof: Cid) -> Result<(), String> {
        let signed = make_invocation(
            vec![(
                self.space.clone().to_resource(
                    "kv".parse().unwrap(),
                    Some("docs".parse().unwrap()),
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

    async fn delegate(&self, token: &str) -> Result<TransactResult, String> {
        self.db
            .delegate(deleg(token))
            .await
            .map_err(|error| error.to_string())
    }

    async fn delegate_batch(&self, tokens: &[&str]) -> Result<TransactResult, String> {
        self.db
            .delegate_batch(tokens.iter().map(|token| deleg(token)).collect())
            .await
            .map_err(|error| error.to_string())
    }

    /// The session root (owner → session key) and a child the session key
    /// made before any retire (session key → holder), both stored.
    async fn signed_in(&self) -> (Cid, String, Cid) {
        let root = self.delegation(&self.owner, &self.session_did(), vec![]);
        self.delegate(&root).await.unwrap();
        let root_cid = cid_of(&root);
        let child = self.delegation(&self.session, &self.holder_did(), vec![root_cid]);
        self.delegate(&child).await.unwrap();
        (root_cid, child.clone(), cid_of(&child))
    }
}

fn cid_of(token: &str) -> Cid {
    crate::hash::hash(token.as_bytes()).to_cid(0x55)
}

fn deleg(token: &str) -> Delegation {
    Delegation::from_header_ser::<TinyCloudDelegation>(token).unwrap()
}

fn assert_retired<T: std::fmt::Debug>(result: Result<T, String>, what: &str) {
    match result {
        Err(error) => assert!(
            error.starts_with("session_retired: "),
            "{what}: unexpected refusal {error}"
        ),
        Ok(value) => panic!("{what}: expected a session_retired refusal, got {value:?}"),
    }
}

async fn on_conn(
    conn: sea_orm::DatabaseConnection,
    dir: Option<tempfile::TempDir>,
    pg: Option<crate::test_support::PostgresTestSchema>,
) -> Fx {
    let db = SpaceDatabase::new(
        conn,
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap();
    let owner = JWK::generate_ed25519().unwrap();
    let (owner_did, _) = did_vm(&owner);
    let space: SpaceId = format!(
        "tinycloud:{}:tc3443",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    space::ActiveModel {
        id: Set(SpaceIdWrap(space.clone())),
    }
    .insert(&db.conn)
    .await
    .unwrap();
    Fx {
        db,
        owner,
        session: JWK::generate_ed25519().unwrap(),
        holder: JWK::generate_ed25519().unwrap(),
        space,
        _dir: dir,
        _pg: pg,
        created: now(),
    }
}

async fn sqlite_fx() -> Fx {
    let dir = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        dir.path().join("retire.sqlite").display()
    );
    on_conn(
        sea_orm::Database::connect(url).await.unwrap(),
        Some(dir),
        None,
    )
    .await
}

async fn pg_fx(test: &str) -> Option<Fx> {
    let pg = crate::test_support::PostgresTestSchema::new(test).await?;
    let conn = pg.conn.clone();
    Some(on_conn(conn, None, Some(pg)).await)
}

/// Self-revoke, pre-retire children, post-retire children on the single and
/// batch paths, resubmission of a stored child, an untouched descendant,
/// and a session root posted again.
async fn retire_scenario(f: Fx) {
    let (root_cid, child, child_cid) = f.signed_in().await;
    f.invoke(&f.session, root_cid).await.unwrap();
    f.invoke(&f.holder, child_cid).await.unwrap();

    let first = f.db.retire_session(&f.session_did(), TTL).await.unwrap();
    let again = f.db.retire_session(&f.session_did(), TTL).await.unwrap();
    assert_eq!(first, again, "a repeat retire keeps the first time");

    // The session key's own invocation is refused.
    assert_retired(f.invoke(&f.session, root_cid).await, "self invoke");
    // A child stored before the retire still authorizes its holder.
    f.invoke(&f.holder, child_cid).await.unwrap();
    // A descendant whose delegator is not the session key is not refused.
    let grandchild_holder = JWK::generate_ed25519().unwrap();
    let grandchild = f.delegation(&f.holder, &did_vm(&grandchild_holder).0, vec![child_cid]);
    f.delegate(&grandchild).await.unwrap();
    f.invoke(&grandchild_holder, cid_of(&grandchild))
        .await
        .unwrap();

    // A new child of the session key is refused on the single and batch paths.
    let late = f.delegation(&f.session, &f.holder_did(), vec![root_cid]);
    assert_retired(f.delegate(&late).await, "single /delegate");
    assert_retired(f.delegate_batch(&[&late]).await, "batch");
    assert!(
        delegation::Entity::find_by_id(crate::hash::hash(late.as_bytes()))
            .one(&f.db.conn)
            .await
            .unwrap()
            .is_none()
    );

    // The stored child, resubmitted, answers as already registered.
    let child_hash = crate::hash::hash(child.as_bytes());
    let single = f.delegate(&child).await.unwrap();
    assert_eq!(single.delegation_cids, vec![child_hash]);
    f.delegate_batch(&[&child]).await.unwrap();

    // The owner may still post a session root to the retired key.
    let root_again = f.delegation(&f.owner, &f.session_did(), vec![]);
    f.delegate(&root_again).await.unwrap();
}

#[tokio::test]
async fn sqlite_retired_session_refuses_itself_and_new_children_only() {
    retire_scenario(sqlite_fx().await).await;
}

#[tokio::test]
async fn postgres_retired_session_refuses_itself_and_new_children_only() {
    let Some(f) = pg_fx("postgres_retired_session_refuses_itself_and_new_children_only").await
    else {
        return;
    };
    retire_scenario(f).await;
}

/// A chain delegation from the retired key first seen after the retire (one
/// that raced it) is refused at invoke; a NULL first-seen time passes.
async fn race_scenario(f: Fx) {
    let (_, child, child_cid) = f.signed_in().await;
    let retired_at = f.db.retire_session(&f.session_did(), TTL).await.unwrap();
    let conn = &f.db.conn;
    let child_id = crate::hash::hash(child.as_bytes());
    let set_first_seen = move |first_seen: Option<OffsetDateTime>| {
        delegation::Entity::update_many()
            .col_expr(
                delegation::Column::FirstSeenAt,
                sea_orm::sea_query::Expr::value(first_seen),
            )
            .filter(delegation::Column::Id.eq(child_id))
            .exec(conn)
    };
    set_first_seen(Some(retired_at + time::Duration::seconds(1)))
        .await
        .unwrap();
    assert_retired(f.invoke(&f.holder, child_cid).await, "raced child");

    set_first_seen(None).await.unwrap();
    f.invoke(&f.holder, child_cid).await.unwrap();
}

#[tokio::test]
async fn sqlite_child_first_seen_after_retire_is_refused_at_invoke() {
    race_scenario(sqlite_fx().await).await;
}

#[tokio::test]
async fn postgres_child_first_seen_after_retire_is_refused_at_invoke() {
    let Some(f) = pg_fx("postgres_child_first_seen_after_retire_is_refused_at_invoke").await else {
        return;
    };
    race_scenario(f).await;
}

/// The node records when it first stored a delegation, and a resubmission
/// keeps that time.
#[tokio::test]
async fn first_seen_is_set_on_insert_and_kept_on_resubmit() {
    let f = sqlite_fx().await;
    let before = crate::models::session_retire::stored_now();
    let (_, child, _) = f.signed_in().await;
    let id = crate::hash::hash(child.as_bytes());
    let conn = &f.db.conn;
    let first_seen = move || async move {
        delegation::Entity::find_by_id(id)
            .one(conn)
            .await
            .unwrap()
            .unwrap()
            .first_seen_at
            .unwrap()
    };
    let stored = first_seen().await;
    assert!(stored >= before);
    f.delegate(&child).await.unwrap();
    f.delegate_batch(&[&child]).await.unwrap();
    assert_eq!(first_seen().await, stored);
}

/// An expired retire row neither refuses nor survives a prune.
#[tokio::test]
async fn expired_retire_does_not_refuse_and_is_pruned() {
    let f = sqlite_fx().await;
    let (root_cid, _, _) = f.signed_in().await;
    f.db.retire_session(&f.session_did(), TTL).await.unwrap();
    assert_retired(f.invoke(&f.session, root_cid).await, "live retire");

    crate::models::session_retire::Entity::update_many()
        .col_expr(
            crate::models::session_retire::Column::ExpiresAt,
            sea_orm::sea_query::Expr::value(OffsetDateTime::now_utc() - time::Duration::seconds(1)),
        )
        .exec(&f.db.conn)
        .await
        .unwrap();
    f.invoke(&f.session, root_cid).await.unwrap();
    let late = f.delegation(&f.session, &f.holder_did(), vec![root_cid]);
    f.delegate(&late).await.unwrap();

    assert_eq!(f.db.prune_session_retires().await.unwrap(), 1);
    assert!(crate::models::session_retire::Entity::find()
        .all(&f.db.conn)
        .await
        .unwrap()
        .is_empty());
}
