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
