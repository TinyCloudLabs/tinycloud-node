use super::*;
use sea_orm::{Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;

const OWNER: &str = "did:pkh:eip155:1:0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed";
fn rings() -> Rings {
    struct Source;
    impl NewRootSource for Source {
        fn new_root(&self) -> Result<Zeroizing<[u8; 32]>, Error> {
            Ok(Zeroizing::new([10; 32]))
        }
    }
    Rings::from_source(&Source, [8; 32], [7; 32], [9; 32]).unwrap()
}
async fn database() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    crate::migrations::Migrator::up(&db, None).await.unwrap();
    db
}
pub(super) async fn exec(db: &impl ConnectionTrait, sql: &str, values: Vec<Value>) {
    db.execute(bound(db.get_database_backend(), sql, values))
        .await
        .unwrap();
}

async fn actors(db: &impl ConnectionTrait) {
    exec(db, "INSERT INTO actor (id) VALUES ('owner'), ('node'), ('historical-owner'), ('historical-node') ON CONFLICT DO NOTHING", vec![]).await;
}

pub(super) async fn hook(db: &impl ConnectionTrait, id: &str, bytes: Vec<u8>) {
    exec(db, "INSERT INTO hook_subscription (id,subscriber_did,space_id,target_service,callback_url,encrypted_secret,secret_key_id,active,created_at) VALUES (?, 'subscriber', 'space', 'kv', 'https://invalid.test', ?, 'primary', TRUE, 'now')", vec![id.into(), bytes.into()]).await;
}

pub(super) async fn fixtures(db: &impl ConnectionTrait) {
    actors(db).await;
    let Rings { seals: seal, .. } = rings();
    let backend = LocalOneOfOneBackend::new(seal.clone());
    for (name, secret_byte) in [("alpha", 31), ("beta", 32)] {
        let network = NetworkId::new(OWNER, name).unwrap().to_string();
        let secret = StaticSecret::from([secret_byte; 32]);
        exec(db, "INSERT INTO encryption_network (network_id,owner_did,name,alg,key_version,public_key,state,threshold_n,threshold_t,key_backend,sealed_private_key,created_at,updated_at) VALUES (?, ?, ?, 'X25519-AES256GCM', 1, ?, 'active', 1, 1, 'local-1of1', ?, 'now', 'now')", vec![network.clone().into(), OWNER.into(), name.into(), PublicKey::from(&secret).as_bytes().to_vec().into(), ColumnEncryption::new([9; 32]).encrypt_legacy(secret.as_bytes()).into()]).await;
        for path in ["apps/app/a", "apps/app/z"] {
            let seed = KeySeed::from_bytes([43; 32]);
            let public = backend
                .derive_named_public_key(&secret, &format!("{network}/{path}"), Some(&seed))
                .unwrap();
            exec(db, "INSERT INTO encryption_network_key (network_id,key_path,kind,state,public_key,sealed_seed,key_version,created_at,updated_at) VALUES (?, ?, 'deletable', 'active', ?, ?, 1, 'now', 'now')", vec![network.clone().into(), path.into(), public.into(), ColumnEncryption::new([9; 32]).encrypt_legacy(&[43; 32]).into()]).await;
        }
    }
    hook(
        db,
        "hook",
        ColumnEncryption::new([7; 32]).encrypt_legacy(b"webhook-secret"),
    )
    .await;
    let policy = br#"{"policy":"identity"}"#;
    let delegation = b"synthetic enforcement dag-cbor bytes";
    let enforcement_cid = raw_sha256_cid(delegation);
    let record = serde_json::to_vec(
        &serde_json::json!({"cid": enforcement_cid, "dagCbor": URL_SAFE_NO_PAD.encode(delegation)}),
    )
    .unwrap();
    exec(db, "INSERT INTO owner_share_policy (policy_cid,registration_cid,owner_delegation_cid,enforcement_delegation_cid,policy_bytes,enforcement_delegation_bytes,policy_proof,policy_digest,matcher_digest,content_source_digest,owner_did,share_key_did,enforcer_did,node_audience,target_origin,space_id,resource_kind,resource_path,actions,registered_at,expires_at) VALUES (?, 'registration', 'owner-delegation', ?, ?, ?, 'proof', 'digest', 'matcher', 'content', 'owner', 'share', 'node', 'node', 'https://invalid.test', 'space', 'kv', '', '[]', 'now', 'later')", vec![raw_sha256_cid(policy).into(), enforcement_cid.into(), ColumnEncryption::new([7; 32]).encrypt_legacy(policy).into(), ColumnEncryption::new([7; 32]).encrypt_legacy(&record).into()]).await;
    for table in ["delegation", "invocation"] {
        let plaintext = if table == "delegation" {
            use tinycloud_auth::ssi::jwk::{Algorithm, JWK};
            crate::test_support::did_resolution::signed_ucan(
                OWNER,
                &JWK::generate_ed25519().unwrap(),
                Algorithm::EdDSA,
            )
            .encode()
            .unwrap()
        } else {
            format!("synthetic {table} serialization")
        };
        let id: Vec<u8> = hash(plaintext.as_bytes()).into();
        let bytes = ColumnEncryption::new([7; 32]).encrypt_legacy(plaintext.as_bytes());
        let sql = if table == "delegation" {
            "INSERT INTO delegation (id,delegator,delegatee,serialization) VALUES (?, 'owner', 'node', ?)"
        } else {
            "INSERT INTO invocation (id,invoker,issued_at,serialization) VALUES (?, 'owner', '2026-11-06T00:00:00Z', ?)"
        };
        exec(db, sql, vec![id.into(), bytes.into()]).await;
    }
}

async fn exercise(db: &DatabaseConnection) {
    fixtures(db).await;
    let rings = rings();
    for (id, kid) in [("old-purpose", 1), ("new-purpose", 2)] {
        let bytes = rings.webhooks.for_kid(kid).unwrap().encrypt(
            b"hook",
            RowBinding::new("hook_subscription", "encrypted_secret", &[id.as_bytes()]),
        );
        hook(db, id, bytes).await;
        exec(
            db,
            "UPDATE hook_subscription SET encrypted_secret_format=2 WHERE id=?",
            vec![id.into()],
        )
        .await;
    }
    let before = census(db).await.unwrap();
    assert!(before.iter().any(|c| c.legacy > 0));
    activate(db, &rings).await.unwrap();
    assert!(check_writer(db, Some(&rings.columns.for_kid(1).unwrap()))
        .await
        .is_err());
    // Fail after a CAS, before commit: ciphertext, cursor and count all roll back.
    assert!(step_page(db, &rings, 2, Some(1)).await.is_err());
    assert_eq!(progress(db).await.unwrap().rewritten, 0);
    assert_eq!(census(db).await.unwrap()[0].legacy, before[0].legacy);
    // A committed batch followed by process loss must resume from its cursor.
    assert!(!step(db, &rings, 1).await.unwrap().complete);
    let checkpoint = progress(db).await.unwrap();
    assert_eq!(checkpoint.rewritten, 1);
    loop {
        // The actual boot constructor validates alias backfill in each mixed state.
        use crate::{db::SpaceDatabase, keys::StaticSecret, storage::memory::MemoryStore};
        let boot = SpaceDatabase::new_with_encryption(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![31; 32]).unwrap(),
            Some(rings.columns.clone()),
        )
        .await;
        assert!(boot.is_ok(), "mixed state boot failed: {:?}", boot.err());
        if step(db, &rings, 1).await.unwrap().complete {
            break;
        }
    }
    let after = census(db).await.unwrap();
    assert!(after
        .iter()
        .all(|c| c.legacy == 0 && c.kids.keys().all(|k| *k == 2)));
    let done = progress(db).await.unwrap().rewritten;
    assert!(step(db, &rings, 10).await.unwrap().complete);
    assert_eq!(progress(db).await.unwrap().rewritten, done);
    // The database fence rejects stale writers, including inserts behind cursor.
    let stale = ColumnEncryption::new([7; 32]).encrypt_legacy(b"stale");
    assert!(db
        .execute(bound(
            db.get_database_backend(),
            "UPDATE hook_subscription SET encrypted_secret=?",
            vec![stale.into()]
        ))
        .await
        .is_err());
}
#[tokio::test]
async fn sqlite_resume_mixed_kids_and_fence() {
    exercise(&database().await).await;
}
#[tokio::test]
async fn postgres_resume_mixed_kids_and_fence() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey").await else {
        return;
    };
    exercise(&f.conn).await;
}

#[tokio::test]
async fn integrity_failure_aborts_at_first_bad_row_without_advancing() {
    let db = database().await;
    fixtures(&db).await;
    let rings = rings();
    exec(
        &db,
        "UPDATE encryption_network SET public_key=?",
        vec![vec![0u8; 32].into()],
    )
    .await;
    activate(&db, &rings).await.unwrap();
    assert!(matches!(
        step(&db, &rings, 10).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(&db).await.unwrap().rewritten, 0);
    assert_eq!(census(&db).await.unwrap()[0].legacy, 2);
}

#[test]
fn mixed_seals_and_wrap_v2_survive_root_change() {
    use crate::encryption_network::backend::*;
    let old = LocalOneOfOneBackend::new(ColumnEncryption::new([9; 32]));
    let new = LocalOneOfOneBackend::new(rings().seals);
    let generated = old.generate().unwrap();
    assert!(new
        .open_network_secret(&generated.sealed_private_key)
        .is_ok());
    let (seed, bytes) = old.generate_seed().unwrap();
    assert!(new.open_seed(&bytes).is_ok());
    drop(seed);
    let secret = StaticSecret::from([42; 32]);
    let context = KeyWrapContext {
        purpose: KeyWrapPurpose::NetworkKey,
        network_id: "",
        key_path: "docs",
        key_version: 1,
        metadata: None,
    };
    let wrapped = wrap_to_public_key_with_context(
        PublicKey::from(&secret).as_bytes(),
        b"symmetric",
        &context,
        KeyWrapVersion::V2,
    )
    .unwrap();
    let seal = rings()
        .seals
        .encrypt(secret.as_bytes(), NETWORK_SEAL_BINDING);
    assert_eq!(new.unwrap(&seal, &wrapped, &context).unwrap(), b"symmetric");
}
