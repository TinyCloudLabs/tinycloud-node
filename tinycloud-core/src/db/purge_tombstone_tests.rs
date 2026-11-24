//! TC-4092: a revocation that records GC deletes is remembered by a
//! `revocation_tombstone`, so the same signed delegation, in any encoding, is
//! not registered again. Un-revoked purged delegations register again.
use super::purge_readmission_tests::{cid_of, deleg, key, token};
use super::*;
use crate::models::delegation::{DelegationError, DelegationRegistration, Error as SaveError};
use crate::models::revocation::RevocationCode;
use crate::storage::memory::MemoryStore;
use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use k256::ecdsa::SigningKey;
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashSet};
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudRevocation},
    cacaos::{
        siwe::{encode_eip55, Message, Version},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature, SiweCacao},
    },
    ipld_core::ipld::Ipld,
    siwe_recap::Capability as RecapCapability,
};

type TestDb = SpaceDatabase<sea_orm::DatabaseConnection, MemoryStore, StaticSecret>;

async fn count(conn: &sea_orm::DatabaseConnection, table: &str) -> i64 {
    conn.query_one(Statement::from_string(
        conn.get_database_backend(),
        format!("SELECT COUNT(*) AS n FROM {table}"),
    ))
    .await
    .unwrap()
    .unwrap()
    .try_get::<i64>("", "n")
    .unwrap()
}

async fn open(conn: sea_orm::DatabaseConnection) -> TestDb {
    SpaceDatabase::new(
        conn,
        MemoryStore::default(),
        StaticSecret::new(vec![0x42; 32]).unwrap(),
    )
    .await
    .map_err(|error| error.to_string())
    .unwrap()
}

/// What `complete_space` and the GC sweep do to these records: every listed
/// delegation and every revocation is deleted through `remove_records`.
async fn purge(conn: &sea_orm::DatabaseConnection, deleted: impl IntoIterator<Item = Hash>) {
    let mut deleted: HashSet<Hash> = deleted.into_iter().collect();
    deleted.extend(
        crate::models::revocation::Entity::find()
            .all(conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id),
    );
    let tx = conn.begin().await.unwrap();
    crate::space_purge_records::remove_records_for_test(&tx, &deleted)
        .await
        .unwrap();
    tx.commit().await.unwrap();
}

fn refused_as_revoked(result: Result<(), TxError<MemoryStore, StaticSecret>>, what: &str) {
    match result {
        Ok(_) => panic!("{what}: a revoked delegation was admitted"),
        Err(error) => assert_eq!(
            error.revocation_code(),
            Some(RevocationCode::DelegationRevoked),
            "{what}: {error}"
        ),
    }
}

/// Plain (non-lease) chain: root -> child. The child is revoked, then both
/// are purged. Runs on SQLite and on PostgreSQL (the insert differs).
async fn plain_revoke_purge_repost(conn: sea_orm::DatabaseConnection) {
    let db = open(conn.clone()).await;
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = token(
        0x11,
        &owner_did,
        &host,
        "tinycloud.space/host",
        &[],
        "host",
        now + 3600,
    );
    let root = token(
        0x11,
        &holder1,
        &kv,
        "tinycloud.kv/get",
        &[],
        "root",
        now + 3600,
    );
    let child = token(
        0x21,
        &holder2,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&root)],
        "child",
        now + 3000,
    );
    for t in [&host_token, &root, &child] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let revocation = token(
        0x11,
        &owner_did,
        &format!("urn:cid:{}", cid_of(&child).to_cid(0x55)),
        "tinycloud.delegation/revoke",
        &[],
        "revoke-child",
        now + 600,
    );
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    assert_eq!(count(&conn, "revocation").await, 1);

    purge(&conn, [&host_token, &root, &child].map(|t| cid_of(t))).await;
    assert_eq!(count(&conn, "revocation").await, 0);
    assert_eq!(count(&conn, "delegation").await, 0);
    let tombstones = crate::models::revocation_tombstone::Entity::find()
        .all(&conn)
        .await
        .unwrap();
    assert_eq!(tombstones.len(), 1, "one tombstone for the one revocation");
    assert_eq!(tombstones[0].delegation_canonical, cid_of(&child));
    assert!(
        tombstones[0].delegation_expiry.is_some() && tombstones[0].revoked_at.is_some(),
        "the times are copied for a later prune"
    );

    // Un-revoked purged delegations register again: New, then Existing.
    let process = |t: &str| {
        let conn = conn.clone();
        let delegation = deleg(t);
        async move {
            crate::models::delegation::process_with(
                &conn,
                &delegation,
                None,
                false,
                true,
                None,
                false,
            )
            .await
        }
    };
    assert_eq!(
        process(&root).await.unwrap(),
        DelegationRegistration::New(cid_of(&root))
    );
    assert_eq!(
        process(&root).await.unwrap(),
        DelegationRegistration::Existing(cid_of(&root))
    );
    // The revoked child, parent now stored again, is refused, twice.
    for attempt in 0..2 {
        match process(&child).await {
            Err(SaveError::InvalidDelegation(DelegationError::Revoked(cid))) => {
                assert_eq!(cid, cid_of(&child).to_cid(0x55).to_string())
            }
            other => panic!("attempt {attempt}: expected Revoked, got {other:?}"),
        }
    }
    assert_eq!(
        count(&conn, "delegation").await,
        1,
        "the child is not stored"
    );
    // Through the real entry point, with the status `/delegate` gives it.
    refused_as_revoked(db.delegate(deleg(&child)).await.map(|_| ()), "delegate");
}

#[tokio::test]
async fn tc4092_non_lease_revoke_purge_repost_is_refused_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("tombstone.sqlite").display()
    );
    plain_revoke_purge_repost(sea_orm::Database::connect(url).await.unwrap()).await;
}

/// CI-only: needs `TINYCLOUD_TEST_POSTGRES_URL` (skips locally unless
/// `TINYCLOUD_ALLOW_LOCAL_PG=1`). Exercises the conditional INSERT .. SELECT
/// of `delegation::save` and the purge's tombstone write on PostgreSQL.
#[tokio::test]
async fn postgres_tc4092_non_lease_revoke_purge_repost_is_refused() {
    let Some(url) = crate::test_support::postgres_test_url(
        "postgres_tc4092_non_lease_revoke_purge_repost_is_refused",
    ) else {
        return;
    };
    let admin = sea_orm::Database::connect(sea_orm::ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = format!(
        "tc4092_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options
        .max_connections(4)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let conn = sea_orm::Database::connect(options).await.unwrap();
    let ran = tokio::spawn(plain_revoke_purge_repost(conn)).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    ran.unwrap();
}

/// C2: pruning a tombstone by `delegation_expiry` is safe only because an
/// expired delegation is refused at admission, before and independent of any
/// tombstone.
#[tokio::test]
async fn tc4092_expired_delegation_is_refused_at_admission() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("expired.sqlite").display()
    );
    let conn = sea_orm::Database::connect(url).await.unwrap();
    let _db = open(conn.clone()).await;
    let (_, owner_did, _) = key(0x11);
    let (_, holder, _) = key(0x21);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let kv = format!(
        "tinycloud:{}:default/kv/docs",
        owner_did.strip_prefix("did:").unwrap()
    );
    let expired = token(
        0x11,
        &holder,
        &kv,
        "tinycloud.kv/get",
        &[],
        "expired",
        now - 100,
    );
    let result = crate::models::delegation::process_with(
        &conn,
        &deleg(&expired),
        None,
        false,
        true,
        None,
        false,
    )
    .await;
    assert!(
        matches!(
            result,
            Err(SaveError::InvalidDelegation(DelegationError::InvalidTime))
        ),
        "{result:?}"
    );
    assert_eq!(count(&conn, "delegation").await, 0);
    // The same call with a live expiry registers.
    let live = token(
        0x11,
        &holder,
        &kv,
        "tinycloud.kv/get",
        &[],
        "live",
        now + 600,
    );
    assert!(crate::models::delegation::process_with(
        &conn,
        &deleg(&live),
        None,
        false,
        true,
        None,
        false,
    )
    .await
    .unwrap()
    .is_new());
}

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
    did: String,
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        let did = format!("did:pkh:eip155:1:0x{}", encode_eip55(&address));
        Self { key, address, did }
    }

    fn message(&self, audience: &str, nonce: &str) -> Message {
        let now = OffsetDateTime::now_utc();
        Message {
            scheme: Some("https".parse().unwrap()),
            domain: "tc4092.invalid".parse().unwrap(),
            address: self.address,
            statement: None,
            uri: audience.parse().unwrap(),
            version: Version::V1,
            chain_id: 1,
            nonce: nonce.to_string(),
            issued_at: now.into(),
            expiration_time: Some((now + time::Duration::hours(2)).into()),
            not_before: Some((now - time::Duration::minutes(2)).into()),
            request_id: None,
            resources: vec![],
        }
    }

    fn sign(&self, message: &Message) -> SiweCacao {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(&signature.to_bytes());
        bytes[64] = u8::from(recovery) + 27;
        CacaoPayload::from(message.clone()).sign::<Eip191>(Signature::from(bytes))
    }
}

/// A wallet-signed CACAO has many wire encodings with one canonical form;
/// each encoding has its own raw hash and its own stored row.
#[tokio::test]
async fn tc4092_alternate_encoding_of_a_revoked_purged_cacao_is_refused() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("cacao.sqlite").display()
    );
    let conn = sea_orm::Database::connect(url).await.unwrap();
    let db = open(conn.clone()).await;
    let wallet = Wallet::new(0x31);
    let (_, holder, _) = key(0x21);
    let space = format!(
        "tinycloud:{}:default",
        wallet.did.strip_prefix("did:").unwrap()
    );
    let mut recap = RecapCapability::<serde_json::Value>::new();
    for (resource, ability) in [
        (format!("{space}/space"), "tinycloud.space/host"),
        (format!("{space}/kv/docs"), "tinycloud.kv/get"),
    ] {
        recap.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    let message = recap
        .build_message(wallet.message(&holder, "tc4092-cacao"))
        .unwrap();
    let canonical_header = TinyCloudDelegation::Cacao(Box::new(wallet.sign(&message)))
        .encode()
        .unwrap();
    let canonical = URL_SAFE.decode(&canonical_header).unwrap();
    // Same delegation, signature recovery byte 0/1 instead of 27/28.
    let value: Ipld = serde_ipld_dagcbor::from_slice(&canonical).unwrap();
    let mut v0 = value.clone();
    if let Ipld::Map(root) = &mut v0 {
        if let Ipld::Map(signature) = root.get_mut("s").unwrap() {
            if let Ipld::Bytes(bytes) = signature.get_mut("s").unwrap() {
                bytes[64] -= 27;
            }
        }
    }
    let v0_header = URL_SAFE.encode(serde_ipld_dagcbor::to_vec(&v0).unwrap());
    // Same map, entries in another order.
    let Ipld::Map(root) = &value else { panic!() };
    let mut reordered = vec![0xa3];
    for name in ["s", "p", "h"] {
        reordered.extend(serde_ipld_dagcbor::to_vec(&name).unwrap());
        reordered.extend(serde_ipld_dagcbor::to_vec(root.get(name).unwrap()).unwrap());
    }
    let order_header = URL_SAFE.encode(reordered);
    let canonical_hash = crate::hash::hash(&canonical);
    for header in [&v0_header, &order_header] {
        let (_, bytes) = TinyCloudDelegation::decode(header).unwrap();
        assert_eq!(
            crate::hash::hash(&bytes),
            canonical_hash,
            "same canonical form"
        );
        assert_ne!(
            crate::hash::hash(&URL_SAFE.decode(header).unwrap()),
            canonical_hash,
            "different raw bytes"
        );
    }

    db.delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&v0_header).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    // The owner revokes it by its canonical id.
    let mut revoke = wallet.message(
        &format!("ucan:{}", canonical_hash.to_cid(0x55)),
        "tc4092-revoke",
    );
    revoke.statement = Some("Revoke delegation".to_string());
    let revocation = TinyCloudRevocation::Cacao(Box::new(wallet.sign(&revoke)))
        .encode()
        .unwrap();
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    assert_eq!(count(&conn, "revocation").await, 1);

    let stored: Vec<Hash> = crate::models::delegation::Entity::find()
        .all(&conn)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    purge(&conn, stored).await;
    assert_eq!(count(&conn, "revocation").await, 0);
    assert_eq!(count(&conn, "delegation").await, 0);
    let tombstones = crate::models::revocation_tombstone::Entity::find()
        .all(&conn)
        .await
        .unwrap();
    assert_eq!(tombstones.len(), 1);
    assert_eq!(tombstones[0].delegation_canonical, canonical_hash);

    // The encoding that was stored, another encoding, and the canonical one.
    for (label, header) in [
        ("stored encoding", &v0_header),
        ("map order encoding", &order_header),
        ("canonical encoding", &canonical_header),
    ] {
        refused_as_revoked(
            db.delegate(Delegation::from_header_ser::<TinyCloudDelegation>(header).unwrap())
                .await
                .map(|_| ()),
            label,
        );
    }
    assert_eq!(count(&conn, "delegation").await, 0);
}

/// The runbook's audit queries run, and return counts only.
#[tokio::test]
async fn tc4092_runbook_audit_queries_execute_and_return_counts_only() {
    let runbook = include_str!("../../../docs/runbooks/revocation-tombstone-audit.md");
    let queries: Vec<&str> = runbook
        .split("```sql\n")
        .skip(1)
        .map(|block| block.split("```").next().unwrap())
        .filter(|sql| sql.trim_start().starts_with("SELECT\n"))
        .collect();
    assert_eq!(queries.len(), 2, "the two audit queries");
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("audit.sqlite").display()
    );
    let conn = sea_orm::Database::connect(url).await.unwrap();
    let _db = open(conn.clone()).await;
    for sql in queries {
        let row = conn
            .query_one(Statement::from_string(DbBackend::Sqlite, sql.to_owned()))
            .await
            .unwrap()
            .unwrap();
        for column in row.column_names() {
            assert_eq!(
                row.try_get::<i64>("", &column).unwrap(),
                0,
                "{column}: an empty node counts zero"
            );
        }
    }
}

/// Like `token`, with several resources under one ability.
fn token_for(
    issuer_seed: u8,
    audience: &str,
    resources: &[&str],
    ability: &str,
    parents: &[Hash],
    nonce: &str,
    exp: i64,
) -> String {
    let (jwk, _, method) = key(issuer_seed);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let mut caps =
        tinycloud_auth::ucan_capabilities_object::Capabilities::<serde_json::Value>::new();
    for resource in resources {
        caps.with_action(
            resource.parse().unwrap(),
            ability.parse().unwrap(),
            [BTreeMap::new()],
        );
    }
    tinycloud_auth::ssi::ucan::Payload::<serde_json::Value> {
        issuer: method.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(
            tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds((now - 5) as f64)
                .unwrap(),
        ),
        expiration: tinycloud_auth::ssi::claims::jwt::NumericDate::try_from_seconds(exp as f64)
            .unwrap(),
        nonce: Some(nonce.to_owned()),
        facts: None,
        proof: parents.iter().map(|id| id.to_cid(0x55)).collect(),
        attenuation: caps,
    }
    .sign(tinycloud_auth::ssi::jwk::Algorithm::EdDSA, &jwk)
    .unwrap()
    .encode()
    .unwrap()
}

/// T1 and T2 (PostgreSQL only: the sweep is). An UNEXPIRED parent P and an
/// UNEXPIRED original O both name spaces S1 and S2. S1 is purged by the real
/// `complete_space`; S2 stays hosted and unfenced, so P and O stay as residue.
/// The owner then revokes a child C that names only S2 and a lease L on O.
/// The automatic sweep (`sweep_next`) deletes both with their revocations, as
/// the repository's own r4/r5 test asserts. Re-posting C or L through
/// `SpaceDatabase::delegate` (what `POST /delegate` calls) must be refused and
/// the old lease must not stamp. A child naming only S1, revoked before the
/// purge, is deleted by `complete_space`: tombstones come from BOTH paths.
#[tokio::test]
async fn postgres_tc4092_multi_space_ancestor_sweep_and_complete_both_tombstone() {
    let Some(url) = crate::test_support::postgres_test_url(
        "postgres_tc4092_multi_space_ancestor_sweep_and_complete_both_tombstone",
    ) else {
        return;
    };
    let admin = sea_orm::Database::connect(sea_orm::ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = format!(
        "tc4092m_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options
        .max_connections(4)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let conn = sea_orm::Database::connect(options).await.unwrap();
    let ran = tokio::spawn(multi_space_ancestor(conn)).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    ran.unwrap();
}

async fn multi_space_ancestor(conn: sea_orm::DatabaseConnection) {
    use crate::space_purge_ledger::LedgerKeys;
    let db = open(conn.clone()).await;
    let identity = db.renewal_identity().unwrap().clone();
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let (_, holder3, _) = key(0x23);
    let bare = owner_did.strip_prefix("did:").unwrap();
    let s1: SpaceId = format!("tinycloud:{bare}:first").parse().unwrap();
    let s2: SpaceId = format!("tinycloud:{bare}:second").parse().unwrap();
    let kv = |space: &SpaceId| {
        space
            .clone()
            .to_resource(
                "kv".parse().unwrap(),
                Some("docs".parse().unwrap()),
                None,
                None,
            )
            .to_string()
    };
    let host = |space: &SpaceId| {
        space
            .clone()
            .to_resource("space".parse().unwrap(), None, None, None)
            .to_string()
    };
    let (kv1, kv2) = (kv(&s1), kv(&s2));
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let ability = "tinycloud.kv/get";
    let host1 = token(
        0x11,
        &owner_did,
        &host(&s1),
        "tinycloud.space/host",
        &[],
        "h1",
        now + 3600,
    );
    let host2 = token(
        0x11,
        &owner_did,
        &host(&s2),
        "tinycloud.space/host",
        &[],
        "h2",
        now + 3600,
    );
    // Unexpired parent and original, both on S1 and S2.
    let parent = token_for(
        0x11,
        &holder1,
        &[&kv1, &kv2],
        ability,
        &[],
        "parent",
        now + 3600,
    );
    let original = token_for(
        0x11,
        &holder3,
        &[&kv1, &kv2],
        ability,
        &[],
        "original",
        now + 3600,
    );
    let original_cid = cid_of(&original).to_cid(0x55).to_string();
    let lease = token(
        0x11,
        &identity.renewer_did,
        &format!("urn:cid:{original_cid}"),
        "tinycloud.delegation/renew",
        &[],
        "lease",
        now + 7200,
    );
    // C names only S2 (live); C1 names only S1 (purged).
    let child = token(
        0x21,
        &holder2,
        &kv2,
        ability,
        &[cid_of(&parent)],
        "child",
        now + 3000,
    );
    let child1 = token(
        0x21,
        &holder2,
        &kv1,
        ability,
        &[cid_of(&parent)],
        "child-1",
        now + 3000,
    );
    // A second original that names only S1, with its own lease.
    let original3 = token_for(
        0x11,
        &holder3,
        &[&kv1],
        ability,
        &[],
        "original-3",
        now + 3600,
    );
    let lease3 = token(
        0x11,
        &identity.renewer_did,
        &format!("urn:cid:{}", cid_of(&original3).to_cid(0x55)),
        "tinycloud.delegation/renew",
        &[],
        "lease-3",
        now + 7200,
    );
    for t in [
        &host1, &host2, &parent, &original, &lease, &original3, &lease3, &child, &child1,
    ] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let revoke = |target: &str, nonce: &str| {
        let revocation = token(
            0x11,
            &owner_did,
            &format!("urn:cid:{}", cid_of(target).to_cid(0x55)),
            "tinycloud.delegation/revoke",
            &[],
            nonce,
            now + 600,
        );
        Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap()
    };
    let stamp_request_for = |original: &str, lease: &str, label: &str| {
        let original_cid = cid_of(original).to_cid(0x55).to_string();
        let invocation =
            tinycloud_auth::authorization::TinyCloudInvocation::decode(original).unwrap();
        let mut request = crate::renewal::StampIssue {
            invocation: crate::util::InvocationInfo::try_from(invocation).unwrap(),
            original_cid: original_cid.clone(),
            lease_cid: cid_of(lease).to_cid(0x55).to_string(),
            replay_hash: crate::hash::hash(label.as_bytes()),
            replay_expires_at: now + 600,
        };
        request.invocation.invoker = identity.renewer_did.clone();
        request.invocation.parents = vec![request.lease_cid.parse().unwrap()];
        request.invocation.capabilities = vec![crate::util::Capability {
            resource: format!("urn:cid:{original_cid}").parse().unwrap(),
            ability: "tinycloud.delegation/renew".to_owned().try_into().unwrap(),
            caveats: Default::default(),
        }];
        request
    };
    let stamp_request = |label: &str| stamp_request_for(&original, &lease, label);
    db.issue_renewal_stamp(stamp_request("control"))
        .await
        .expect("control: the live lease stamps");
    db.issue_renewal_stamp(stamp_request_for(&original3, &lease3, "control-3"))
        .await
        .expect("control: the S1-only lease stamps");

    // Fence time (the purge accept transaction writes the space fence and
    // calls this in the same transaction): the lease of the original that
    // names only S1 goes terminal; the lease of the two-space original stays.
    let tx = conn.begin().await.unwrap();
    let stopped = crate::space_purge_records::terminate_space_leases(&tx, &s1.to_string())
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(stopped, 1, "only the S1-only lease is stopped");
    let state_of = |lease: String| {
        let conn = conn.clone();
        async move {
            conn.query_one(Statement::from_sql_and_values(
                DbBackend::Postgres,
                "SELECT state FROM renewal_lease WHERE lease_cid = $1",
                [Vec::<u8>::from(cid_of(&lease)).into()],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<String>("", "state")
            .unwrap()
        }
    };
    assert_eq!(state_of(lease3.clone()).await, "revoked");
    assert_eq!(state_of(lease.clone()).await, "active");
    let stamp = db
        .issue_renewal_stamp(stamp_request_for(&original3, &lease3, "drain-3"))
        .await;
    assert!(
        matches!(
            stamp,
            Err(crate::renewal::RenewalStoreError::LeaseUnavailable)
        ),
        "no stamp for a lease stopped at fence time: {stamp:?}"
    );

    // The owner revokes C1 (S1 only) before the purge.
    db.revoke(revoke(&child1, "revoke-child-1"))
        .await
        .map_err(|error| error.to_string())
        .unwrap();

    // Purge S1 through the real terminal transaction.
    let keys = LedgerKeys::new(
        "test".into(),
        BTreeMap::from([("test".into(), vec![7; 32])]),
    )
    .unwrap();
    let purge_id = format!("{}", uuid::Uuid::from_bytes(rand::random()));
    let target = keys.target_hmac("test", "space", &s1.to_string()).unwrap();
    let accepted_at = OffsetDateTime::now_utc();
    crate::models::space_purge_job::ActiveModel {
        purge_id: Set(purge_id.clone()),
        space: Set(Some(s1.to_string())),
        tombstone_hmac: Set(target.clone()),
        hmac_key_id: Set("test".into()),
        owner_hmac: Set(keys.target_hmac("test", "owner", &owner_did).unwrap()),
        accepted_at: Set(accepted_at),
        phase: Set("objects".into()),
        fence_generation: Set(1),
        updated_at: Set(accepted_at),
        next_attempt_at: Set(accepted_at),
        attempt_count: Set(0),
        last_error_code: Set(None),
        lease_token: Set(None),
        lease_until: Set(None),
    }
    .insert(&conn)
    .await
    .unwrap();
    let lease_token = format!("{}", uuid::Uuid::from_bytes(rand::random()));
    let job = crate::space_purge_worker::claim_specific(&conn, &lease_token, &purge_id)
        .await
        .unwrap()
        .unwrap();
    let record = keys
        .sign(
            "test",
            "space",
            &target,
            &purge_id,
            "complete",
            accepted_at.unix_timestamp(),
        )
        .unwrap();
    assert!(
        crate::space_purge_worker::complete_with_encryption(&conn, &job, &keys, &record, None)
            .await
            .unwrap()
    );
    let stored = |t: &str| {
        let conn = conn.clone();
        let id = cid_of(t);
        async move {
            crate::models::delegation::Entity::find_by_id(id)
                .one(&conn)
                .await
                .unwrap()
                .is_some()
        }
    };
    let tombstoned = || {
        let conn = conn.clone();
        async move {
            crate::models::revocation_tombstone::Entity::find()
                .all(&conn)
                .await
                .unwrap()
                .into_iter()
                .map(|row| row.delegation_canonical)
                .collect::<HashSet<_>>()
        }
    };
    // complete_space: P and O are live through S2 and stay; C1 is gone with
    // its revocation and has a tombstone; C is untouched.
    assert!(stored(&parent).await && stored(&original).await && stored(&child).await);
    assert!(!stored(&child1).await, "C1 deleted by complete_space");
    assert_eq!(
        tombstoned().await,
        HashSet::from([cid_of(&child1)]),
        "complete_space wrote C1's tombstone"
    );
    assert_eq!(count(&conn, "revocation").await, 0);

    // Real revokes of C and of the lease on S2's side.
    for (target, nonce) in [(&child, "revoke-child"), (&lease, "revoke-lease")] {
        db.revoke(revoke(target, nonce))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    assert_eq!(count(&conn, "revocation").await, 2);
    assert!(
        crate::space_purge_records::sweep_next(&conn, &keys, None)
            .await
            .unwrap(),
        "the revokes woke the residue sweep"
    );
    // The sweep deleted C, L and both revocations, and kept P and O.
    assert!(
        stored(&parent).await && stored(&original).await,
        "P and O stay"
    );
    assert!(
        !stored(&child).await && !stored(&lease).await,
        "C and L deleted"
    );
    assert_eq!(count(&conn, "revocation").await, 0);
    assert_eq!(count(&conn, "renewal_lease").await, 0);
    assert_eq!(count(&conn, "renewal_stamp").await, 0);
    assert_eq!(
        tombstoned().await,
        HashSet::from([cid_of(&child1), cid_of(&child), cid_of(&lease)]),
        "sweep_transaction wrote C's and L's tombstones"
    );

    // Real /delegate: refused, not admitted.
    refused_as_revoked(db.delegate(deleg(&child)).await.map(|_| ()), "C re-post");
    // C1 names the purged space: refused (the space is gone), not stored.
    assert!(db.delegate(deleg(&child1)).await.is_err(), "C1 re-post");
    assert!(!stored(&child1).await);
    refused_as_revoked(db.delegate(deleg(&lease)).await.map(|_| ()), "L re-post");
    assert!(!stored(&child).await && !stored(&lease).await);
    assert_eq!(count(&conn, "renewal_lease").await, 0);
    // No stamp on the old lease.
    let stamp = db.issue_renewal_stamp(stamp_request("after")).await;
    assert!(stamp.is_err(), "no stamp after the purge: {stamp:?}");
    assert_eq!(count(&conn, "renewal_stamp").await, 0);
}

/// A Policy/v3 root revoked through its own store (`policy_v3_root.revoked_at`,
/// what `RootRevocation/v1` writes; no `revocation` row) must stay refused
/// after purge deletes that row. A root that was never revoked gets no
/// tombstone and registers again.
async fn policy_root_revoked_purge_repost(conn: sea_orm::DatabaseConnection) {
    let db = open(conn.clone()).await;
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = token(
        0x11,
        &owner_did,
        &host,
        "tinycloud.space/host",
        &[],
        "host",
        now + 3600,
    );
    let root = token(
        0x11,
        &holder1,
        &kv,
        "tinycloud.kv/get",
        &[],
        "root",
        now + 3600,
    );
    let child = token(
        0x21,
        &holder2,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&root)],
        "child",
        now + 3000,
    );
    for t in [&host_token, &root, &child] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    let policy_root =
        |token: &str, revoked_at: Option<&str>| crate::models::policy_v3_root::ActiveModel {
            root_cid: Set(cid_of(token).to_cid(0x55).to_string()),
            policy_cid: Set("policy".to_string()),
            role: Set("policy".to_string()),
            authorization_bytes: Set(vec![1]),
            status_checkpoint_bytes: Set(None),
            previous_checkpoint_digest_hex: Set(None),
            status_sequence: Set(0),
            admission_epoch: Set(0),
            status_checked_at: Set(None),
            status_fresh_until: Set(None),
            revoked_at: Set(revoked_at.map(str::to_string)),
            revocation_bytes: Set(revoked_at.map(|_| vec![2])),
        };
    crate::models::policy_v3_root::Entity::insert_many([
        policy_root(&child, Some("2026-01-01T00:00:00Z")),
        policy_root(&root, None),
    ])
    .exec(&conn)
    .await
    .unwrap();
    assert_eq!(count(&conn, "revocation").await, 0, "no revocation row");

    purge(&conn, [&host_token, &root, &child].map(|t| cid_of(t))).await;
    assert_eq!(count(&conn, "policy_v3_root").await, 0);
    assert_eq!(count(&conn, "delegation").await, 0);
    let tombstones = crate::models::revocation_tombstone::Entity::find()
        .all(&conn)
        .await
        .unwrap();
    assert_eq!(tombstones.len(), 1, "only the revoked root is tombstoned");
    assert_eq!(tombstones[0].delegation_canonical, cid_of(&child));
    assert!(tombstones[0].delegation_expiry.is_some());
    assert_eq!(
        tombstones[0].revoked_at,
        Some(
            OffsetDateTime::parse(
                "2026-01-01T00:00:00Z",
                &time::format_description::well_known::Rfc3339
            )
            .unwrap()
        ),
        "the revocation time of the row, nothing else"
    );

    let process = |t: &str| {
        let conn = conn.clone();
        let delegation = deleg(t);
        async move {
            crate::models::delegation::process_with(
                &conn,
                &delegation,
                None,
                false,
                true,
                None,
                false,
            )
            .await
        }
    };
    assert_eq!(
        process(&root).await.unwrap(),
        DelegationRegistration::New(cid_of(&root))
    );
    match process(&child).await {
        Err(SaveError::InvalidDelegation(DelegationError::Revoked(cid))) => {
            assert_eq!(cid, cid_of(&child).to_cid(0x55).to_string())
        }
        other => panic!("expected Revoked, got {other:?}"),
    }
    refused_as_revoked(db.delegate(deleg(&child)).await.map(|_| ()), "delegate");
}

#[tokio::test]
async fn tc4092_policy_v3_root_revoked_in_its_own_store_stays_refused_after_purge_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("policy-root.sqlite").display()
    );
    policy_root_revoked_purge_repost(sea_orm::Database::connect(url).await.unwrap()).await;
}

#[tokio::test]
async fn postgres_tc4092_policy_v3_root_revoked_in_its_own_store_stays_refused_after_purge() {
    let Some(url) = crate::test_support::postgres_test_url(
        "postgres_tc4092_policy_v3_root_revoked_in_its_own_store_stays_refused_after_purge",
    ) else {
        return;
    };
    let admin = sea_orm::Database::connect(sea_orm::ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = format!(
        "tc4092p_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options
        .max_connections(4)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let conn = sea_orm::Database::connect(options).await.unwrap();
    let ran = tokio::spawn(policy_root_revoked_purge_repost(conn)).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    ran.unwrap();
}

/// TC-4092: the tombstones, the `revocation` delete and `policy::remove` are
/// one transaction. A database error after the tombstones were written (here a
/// trigger that aborts the delete of `fail_table`, which comes after the
/// tombstone pre-pass, after the `revocation` delete and, for `delegation`,
/// after `policy::remove`) leaves NEITHER done once the caller's transaction
/// rolls back: no tombstone, every revocation, policy and delegation row intact.
/// Without the fault, the same input tombstones both revocations.
async fn purge_is_all_or_nothing(conn: sea_orm::DatabaseConnection, fail_table: &str) {
    let db = open(conn.clone()).await;
    let (_, owner_did, _) = key(0x11);
    let (_, holder1, _) = key(0x21);
    let (_, holder2, _) = key(0x22);
    let space: SpaceId = format!(
        "tinycloud:{}:default",
        owner_did.strip_prefix("did:").unwrap()
    )
    .parse()
    .unwrap();
    let kv = space
        .clone()
        .to_resource(
            "kv".parse().unwrap(),
            Some("docs".parse().unwrap()),
            None,
            None,
        )
        .to_string();
    let host = space
        .clone()
        .to_resource("space".parse().unwrap(), None, None, None)
        .to_string();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let host_token = token(
        0x11,
        &owner_did,
        &host,
        "tinycloud.space/host",
        &[],
        "host",
        now + 3600,
    );
    let root = token(
        0x11,
        &holder1,
        &kv,
        "tinycloud.kv/get",
        &[],
        "root",
        now + 3600,
    );
    let child = token(
        0x21,
        &holder2,
        &kv,
        "tinycloud.kv/get",
        &[cid_of(&root)],
        "child",
        now + 3000,
    );
    for t in [&host_token, &root, &child] {
        db.delegate(deleg(t))
            .await
            .map_err(|error| error.to_string())
            .unwrap();
    }
    // One revocation in each store: `child` in `revocation`, `root` in
    // `policy_v3_root.revoked_at`.
    let revocation = token(
        0x11,
        &owner_did,
        &format!("urn:cid:{}", cid_of(&child).to_cid(0x55)),
        "tinycloud.delegation/revoke",
        &[],
        "revoke-child",
        now + 600,
    );
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&revocation).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    crate::models::policy_v3_root::Entity::insert(crate::models::policy_v3_root::ActiveModel {
        root_cid: Set(cid_of(&root).to_cid(0x55).to_string()),
        policy_cid: Set("policy".to_string()),
        role: Set("policy".to_string()),
        authorization_bytes: Set(vec![1]),
        status_checkpoint_bytes: Set(None),
        previous_checkpoint_digest_hex: Set(None),
        status_sequence: Set(0),
        admission_epoch: Set(0),
        status_checked_at: Set(None),
        status_fresh_until: Set(None),
        revoked_at: Set(Some("2026-01-01T00:00:00Z".to_string())),
        revocation_bytes: Set(Some(vec![2])),
    })
    .exec(&conn)
    .await
    .unwrap();
    let rows = |conn: &sea_orm::DatabaseConnection| {
        let conn = conn.clone();
        async move {
            (
                count(&conn, "revocation").await,
                count(&conn, "delegation").await,
                count(&conn, "policy_v3_root").await,
                count(&conn, "revocation_tombstone").await,
            )
        }
    };
    assert_eq!(rows(&conn).await, (1, 3, 1, 0));

    let mut deleted: HashSet<Hash> = [&host_token, &root, &child]
        .map(|t| cid_of(t))
        .into_iter()
        .collect();
    deleted.extend(
        crate::models::revocation::Entity::find()
            .all(&conn)
            .await
            .unwrap()
            .into_iter()
            .map(|row| row.id),
    );

    // The fault: the delete of `fail_table` rows aborts.
    let backend = conn.get_database_backend();
    let (install, remove): (Vec<String>, Vec<String>) = match backend {
        sea_orm::DatabaseBackend::Postgres => (
            vec![
                "CREATE FUNCTION tc4092_fail() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'tc4092 injected'; END $$".to_string(),
                format!("CREATE TRIGGER tc4092_fail BEFORE DELETE ON {fail_table} FOR EACH ROW EXECUTE FUNCTION tc4092_fail()"),
            ],
            vec![
                format!("DROP TRIGGER tc4092_fail ON {fail_table}"),
                "DROP FUNCTION tc4092_fail()".to_string(),
            ],
        ),
        _ => (
            vec![format!(
                "CREATE TRIGGER tc4092_fail BEFORE DELETE ON {fail_table} BEGIN SELECT RAISE(ABORT, 'tc4092 injected'); END"
            )],
            vec!["DROP TRIGGER tc4092_fail".to_string()],
        ),
    };
    for sql in &install {
        conn.execute_unprepared(sql).await.unwrap();
    }
    let tx = conn.begin().await.unwrap();
    let error = crate::space_purge_records::remove_records_for_test(&tx, &deleted)
        .await
        .expect_err("the injected fault must fail the purge");
    assert!(error.to_string().contains("tc4092 injected"), "{error}");
    tx.rollback().await.unwrap();
    assert_eq!(
        rows(&conn).await,
        (1, 3, 1, 0),
        "a failed purge leaves no tombstone and every row in place ({fail_table})"
    );

    // Control: the same purge without the fault does both.
    for sql in &remove {
        conn.execute_unprepared(sql).await.unwrap();
    }
    let tx = conn.begin().await.unwrap();
    crate::space_purge_records::remove_records_for_test(&tx, &deleted)
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        rows(&conn).await,
        (0, 0, 0, 2),
        "both revocations remembered"
    );
    // The ticket check (signed URLs, hook tickets) must not forget either
    // revocation: the delegations are gone, the tombstones remain. The purged
    // host delegation was never revoked and has no tombstone.
    let cited = |t: &String| [cid_of(t).to_cid(0x55)];
    for revoked in [&child, &root] {
        assert_eq!(
            db.delegation_chains_revocation(&cited(revoked))
                .await
                .unwrap(),
            Some(RevocationCode::DelegationRevoked),
            "ticket authority stays revoked after the purge"
        );
    }
    assert_eq!(
        db.delegation_chains_revocation(&cited(&host_token))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn tc4092_failed_delegation_delete_rolls_back_tombstones_and_leaves_rows_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("atomic-delegation.sqlite").display()
    );
    purge_is_all_or_nothing(sea_orm::Database::connect(url).await.unwrap(), "delegation").await;
}

#[tokio::test]
async fn tc4092_failed_policy_root_delete_rolls_back_tombstones_and_leaves_rows_on_sqlite() {
    let directory = tempfile::tempdir().unwrap();
    let url = format!(
        "sqlite://{}?mode=rwc",
        directory.path().join("atomic-policy.sqlite").display()
    );
    purge_is_all_or_nothing(
        sea_orm::Database::connect(url).await.unwrap(),
        "policy_v3_root",
    )
    .await;
}

async fn postgres_all_or_nothing(fail_table: &'static str, name: &'static str) {
    let Some(url) = crate::test_support::postgres_test_url(name) else {
        return;
    };
    let admin = sea_orm::Database::connect(sea_orm::ConnectOptions::new(url.clone()))
        .await
        .unwrap();
    let schema = format!(
        "tc4092a_{}_{}",
        std::process::id(),
        OffsetDateTime::now_utc().unix_timestamp_nanos()
    );
    admin
        .execute_unprepared(&format!("CREATE SCHEMA {schema}"))
        .await
        .unwrap();
    let mut options = sea_orm::ConnectOptions::new(url);
    options
        .max_connections(4)
        .sqlx_logging(false)
        .set_schema_search_path(schema.clone());
    let conn = sea_orm::Database::connect(options).await.unwrap();
    let ran = tokio::spawn(purge_is_all_or_nothing(conn, fail_table)).await;
    admin
        .execute_unprepared(&format!("DROP SCHEMA {schema} CASCADE"))
        .await
        .unwrap();
    ran.unwrap();
}

#[tokio::test]
async fn postgres_tc4092_failed_delegation_delete_rolls_back_tombstones_and_leaves_rows() {
    postgres_all_or_nothing(
        "delegation",
        "postgres_tc4092_failed_delegation_delete_rolls_back_tombstones_and_leaves_rows",
    )
    .await;
}

#[tokio::test]
async fn postgres_tc4092_failed_policy_root_delete_rolls_back_tombstones_and_leaves_rows() {
    postgres_all_or_nothing(
        "policy_v3_root",
        "postgres_tc4092_failed_policy_root_delete_rolls_back_tombstones_and_leaves_rows",
    )
    .await;
}
