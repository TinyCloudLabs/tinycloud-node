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
    exec(db, "INSERT INTO hook_subscription (id,subscriber_did,space_id,target_service,callback_url,encrypted_secret,secret_key_id,active,created_at,encrypted_secret_format) VALUES (?, 'subscriber', 'space', 'kv', 'https://invalid.test', ?, 'primary', TRUE, 'now', ?)", vec![id.into(), bytes.clone().into(), (if bytes.first()==Some(&2) {2i16} else {0i16}).into()]).await;
}

pub(super) async fn fixtures(db: &impl ConnectionTrait) {
    actors(db).await;
    let Rings { seals: seal, .. } = rings();
    let backend = LocalOneOfOneBackend::new(seal.clone());
    for (name, secret_byte) in [("alpha", 31), ("beta", 32)] {
        let network = NetworkId::new(OWNER, name).unwrap().to_string();
        let secret = StaticSecret::from([secret_byte; 32]);
        exec(db, "INSERT INTO encryption_network (network_id,owner_did,name,alg,key_version,public_key,state,threshold_n,threshold_t,key_backend,sealed_private_key,created_at,updated_at) VALUES (?, ?, ?, 'X25519-AES256GCM', 1, ?, 'active', 1, 1, 'local-one-of-one', ?, 'now', 'now')", vec![network.clone().into(), OWNER.into(), name.into(), PublicKey::from(&secret).as_bytes().to_vec().into(), ColumnEncryption::new([9; 32]).encrypt_legacy(secret.as_bytes()).into()]).await;
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
    for (id, kid) in [("old-purpose", 1)] {
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
    let rings = activate(db, &rings).await.unwrap();
    let id = "new-purpose";
    hook(
        db,
        id,
        rings.webhooks.encrypt(
            b"hook",
            RowBinding::new("hook_subscription", "encrypted_secret", &[id.as_bytes()]),
        ),
    )
    .await;
    exec(
        db,
        "UPDATE hook_subscription SET encrypted_secret_format=2 WHERE id=?",
        vec![id.into()],
    )
    .await;
    assert!(check_writer(
        db,
        Some(&rings.columns.for_kid(1).unwrap()),
        Some(&rings.webhooks),
        Some(&rings.seals)
    )
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
        let boot = SpaceDatabase::new_with_storage_rings(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![31; 32]).unwrap(),
            rings.clone(),
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
    let rings = activate(&db, &rings).await.unwrap();
    assert!(matches!(
        step(&db, &rings, 10).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(&db).await.unwrap().rewritten, 0);
    assert_eq!(census(&db).await.unwrap()[0].legacy, 2);
}

#[test]
fn existing_v1_and_v2_kid0_seals_and_wrap_v2_survive_root_change() {
    use crate::encryption_network::backend::*;
    let old = LocalOneOfOneBackend::new(ColumnEncryption::new([9; 32]));
    let new = LocalOneOfOneBackend::new(rings().seals);
    let generated = old.generate("").unwrap();
    assert_eq!(&generated.sealed_private_key[..2], &[2, 0]);
    assert!(rings().seals.has_key(0));
    assert!(!rings().seals.has_key(1));
    assert!(rings().seals.has_key(2));
    let legacy_secret = StaticSecret::from([41; 32]);
    let legacy = ColumnEncryption::new([9; 32]).encrypt_legacy(legacy_secret.as_bytes());
    assert!(new
        .open_network_secret(&legacy, "", PublicKey::from(&legacy_secret).as_bytes())
        .is_ok());

    assert!(new
        .open_network_secret(&generated.sealed_private_key, "", &generated.public_key)
        .is_ok());
    let (seed, bytes) = old.generate_seed("", "docs").unwrap();
    assert!(new.open_seed(&bytes, "", "docs").is_ok());
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
    let seal = rings().seals.encrypt(
        secret.as_bytes(),
        RowBinding::new("encryption_network", "sealed_private_key", &[b""]),
    );
    assert_eq!(
        new.unwrap(
            &seal,
            PublicKey::from(&secret).as_bytes(),
            &wrapped,
            &context
        )
        .unwrap(),
        b"symmetric"
    );
}

#[tokio::test]
async fn overlap_precedes_fence_and_writer_switch() {
    let db = database().await;
    let overlap = rings();
    assert_eq!(overlap.columns.write_kid(), 1);
    assert_eq!(overlap.webhooks.write_kid(), 1);
    assert_eq!(overlap.seals.write_kid(), 0);
    let active = activate(&db, &overlap).await.unwrap();
    assert_eq!(active.columns.write_kid(), 2);
    assert_eq!(active.webhooks.write_kid(), 2);
    assert_eq!(active.seals.write_kid(), 2);
}

#[tokio::test]
async fn boot_refuses_each_mixed_ring_combination() {
    let db = database().await;
    let overlap = rings();
    let active = activate(&db, &overlap).await.unwrap();
    for missing in 0..3 {
        let mut mixed = active.clone();
        match missing {
            0 => mixed.columns = overlap.columns.clone(),
            1 => mixed.webhooks = overlap.webhooks.clone(),
            _ => mixed.seals = overlap.seals.clone(),
        }
        use crate::{db::SpaceDatabase, keys::StaticSecret, storage::memory::MemoryStore};
        assert!(SpaceDatabase::new_with_storage_rings(
            db.clone(),
            MemoryStore::default(),
            StaticSecret::new(vec![31; 32]).unwrap(),
            mixed
        )
        .await
        .is_err());
    }
}

#[test]
fn sealed_rows_reject_transplants_and_wrong_network_public_key() {
    let backend = LocalOneOfOneBackend::new(rings().seals);
    let key = backend.generate("network-a").unwrap();
    assert!(backend
        .open_network_secret(&key.sealed_private_key, "network-a", &key.public_key)
        .is_ok());
    assert!(backend
        .open_network_secret(&key.sealed_private_key, "network-b", &key.public_key)
        .is_err());
    assert!(backend
        .open_network_secret(&key.sealed_private_key, "network-a", &[0; 32])
        .is_err());
    let (_, seed) = backend.generate_seed("network-a", "path-a").unwrap();
    assert!(backend.open_seed(&seed, "network-a", "path-a").is_ok());
    assert!(backend.open_seed(&seed, "network-b", "path-a").is_err());
    assert!(backend.open_seed(&seed, "network-a", "path-b").is_err());
}

async fn verification_review_cases(db: &DatabaseConnection) {
    fixtures(db).await;
    let rings = activate(db, &rings()).await.unwrap();
    loop {
        let page = step(db, &rings, 1).await.unwrap();
        if page.verifying {
            break;
        }
        assert!(!page.complete);
    }
    let first = step(db, &rings, 1).await.unwrap();
    assert!(first.verifying && !first.complete);
    assert_eq!(first.verified, 1);
    // Prefix, size and kid remain valid; final verification must authenticate.
    let rows = select_batch(db, COLUMNS[2], None, 1).await.unwrap();
    let mut corrupt = rows[0].blob.clone().unwrap();
    *corrupt.last_mut().unwrap() ^= 1;
    exec(
        db,
        "UPDATE hook_subscription SET encrypted_secret=?",
        vec![corrupt.into()],
    )
    .await;
    let mut failed = false;
    for _ in 0..100 {
        let before = progress(db).await.unwrap();
        match step(db, &rings, 1).await {
            Ok(page) => {
                assert!(!page.complete);
                assert!(page.verified - before.verified <= 1);
            }
            Err(Error::Verify) => {
                failed = true;
                assert_eq!(progress(db).await.unwrap().verified, before.verified);
                break;
            }
            Err(other) => panic!("unexpected final verification failure: {other}"),
        }
    }
    assert!(failed);
    assert!(!progress(db).await.unwrap().complete);
}
#[tokio::test]
async fn sqlite_final_verification_is_bounded_durable_and_authenticated() {
    verification_review_cases(&database().await).await;
}
#[tokio::test]
async fn postgres_final_verification_is_bounded_durable_and_authenticated() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_verification").await
    else {
        return;
    };
    verification_review_cases(&f.conn).await;
}

async fn orphan_review_case(db: &DatabaseConnection) {
    fixtures(db).await;
    exec(db,"UPDATE encryption_network_key SET network_id=? WHERE network_id=(SELECT MIN(network_id) FROM encryption_network_key)",vec![NetworkId::new(OWNER,"missing").unwrap().to_string().into()]).await;
    let rings = activate(db, &rings()).await.unwrap();
    let mut failed = false;
    for _ in 0..100 {
        match step(db, &rings, 1).await {
            Ok(p) => assert!(!p.complete),
            Err(Error::Integrity { .. }) => {
                failed = true;
                break;
            }
            Err(other) => panic!("unexpected orphan failure: {other}"),
        }
    }
    assert!(failed);
    assert!(!progress(db).await.unwrap().complete);
}
#[tokio::test]
async fn sqlite_orphan_seed_refuses_completion() {
    orphan_review_case(&database().await).await;
}
#[tokio::test]
async fn postgres_orphan_seed_refuses_completion() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_orphan").await
    else {
        return;
    };
    orphan_review_case(&f.conn).await;
}

async fn legacy_seal_review_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let network = NetworkId::new(OWNER, "alpha").unwrap().to_string();
    let old = select_batch(db, COLUMNS[0], None, 1)
        .await
        .unwrap()
        .remove(0)
        .blob
        .unwrap();
    assert!(ColumnEncryption::new([9; 32]).decrypt_legacy(&old).is_ok());
    let active = activate(db, &rings()).await.unwrap();
    while !step(db, &active, 1).await.unwrap().complete {}
    let networks = select_batch(db, COLUMNS[0], None, 10).await.unwrap();
    let backend = LocalOneOfOneBackend::new(active.seals.clone());
    for row in networks {
        let Key::Text(id) = row.key else {
            panic!("network key type");
        };
        let sealed = row.blob.unwrap();
        assert!(ColumnEncryption::new([9; 32])
            .decrypt_legacy(&sealed)
            .is_err());
        assert!(backend
            .open_network_secret(&sealed, &id, row.public_key.as_deref().unwrap())
            .is_ok());
        assert!(backend
            .open_network_secret(
                &sealed,
                "different-network",
                row.public_key.as_deref().unwrap()
            )
            .is_err());
    }
    for row in select_batch(db, COLUMNS[1], None, 10).await.unwrap() {
        let Key::Pair(id, path) = row.key else {
            panic!("seed key type");
        };
        let sealed = row.blob.unwrap();
        assert!(ColumnEncryption::new([9; 32])
            .decrypt_legacy(&sealed)
            .is_err());
        assert!(backend.open_seed(&sealed, &id, &path).is_ok());
        assert!(backend
            .open_seed(&sealed, &network, "different-path")
            .is_err());
    }
}
#[tokio::test]
async fn sqlite_genuine_v1_seals_migrate_to_pk_bound_v2() {
    legacy_seal_review_case(&database().await).await;
}
#[tokio::test]
async fn postgres_genuine_v1_seals_migrate_to_pk_bound_v2() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_legacy_seals").await
    else {
        return;
    };
    legacy_seal_review_case(&f.conn).await;
}

async fn missing_read_review_case(db: &DatabaseConnection) {
    use crate::encryption::EncryptionPurpose;
    let overlap = rings();
    for index in 0..3 {
        let mut incomplete = overlap.clone();
        match index {
            0 => {
                incomplete.columns = ColumnEncryption::for_roots(
                    1,
                    [(1, [8; 32])],
                    [7; 32],
                    EncryptionPurpose::Columns,
                )
                .unwrap()
            }
            1 => {
                incomplete.webhooks = ColumnEncryption::for_roots(
                    1,
                    [(1, [8; 32])],
                    [7; 32],
                    EncryptionPurpose::Webhooks,
                )
                .unwrap()
            }
            _ => incomplete.seals = ColumnEncryption::new([9; 32]),
        }
        let tx = db.begin().await.unwrap();
        assert!(check_writer(
            &tx,
            Some(&incomplete.columns),
            Some(&incomplete.webhooks),
            Some(&incomplete.seals)
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
        assert!(activate(db, &incomplete).await.is_err());
    }
    let premature = overlap.select_writer(2).unwrap();
    let tx = db.begin().await.unwrap();
    assert!(check_writer(
        &tx,
        Some(&premature.columns),
        Some(&premature.webhooks),
        Some(&premature.seals)
    )
    .await
    .is_err());
    tx.rollback().await.unwrap();
    assert!(activate(db, &premature).await.is_err());
    let active = activate(db, &overlap).await.unwrap();
    for index in 0..3 {
        let mut incomplete = active.clone();
        match index {
            0 => {
                incomplete.columns = ColumnEncryption::for_roots(
                    2,
                    [(2, [10; 32])],
                    [7; 32],
                    EncryptionPurpose::Columns,
                )
                .unwrap()
            }
            1 => {
                incomplete.webhooks = ColumnEncryption::for_roots(
                    2,
                    [(2, [10; 32])],
                    [7; 32],
                    EncryptionPurpose::Webhooks,
                )
                .unwrap()
            }
            _ => incomplete.seals = ColumnEncryption::with_keys(2, [(2, [10; 32])]).unwrap(),
        }
        let tx = db.begin().await.unwrap();
        assert!(check_writer(
            &tx,
            Some(&incomplete.columns),
            Some(&incomplete.webhooks),
            Some(&incomplete.seals)
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
    }
    for index in 0..2 {
        let mut incomplete = active.clone();
        let missing_v1 = ColumnEncryption::with_keys(2, [(1, [8; 32]), (2, [10; 32])]).unwrap();
        if index == 0 {
            incomplete.columns = missing_v1;
        } else {
            incomplete.webhooks = missing_v1;
        }
        let tx = db.begin().await.unwrap();
        assert!(check_writer(
            &tx,
            Some(&incomplete.columns),
            Some(&incomplete.webhooks),
            Some(&incomplete.seals)
        )
        .await
        .is_err());
        tx.rollback().await.unwrap();
    }
}
#[tokio::test]
async fn sqlite_boot_requires_old_and_new_read_generations() {
    missing_read_review_case(&database().await).await;
}
#[tokio::test]
async fn postgres_boot_requires_old_and_new_read_generations() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_read_overlap").await
    else {
        return;
    };
    missing_read_review_case(&f.conn).await;
}

async fn null_review_case(db: &DatabaseConnection, seed: bool) {
    fixtures(db).await;
    exec(
        db,
        if seed {
            "UPDATE encryption_network_key SET sealed_seed=NULL"
        } else {
            "UPDATE encryption_network SET sealed_private_key=NULL"
        },
        vec![],
    )
    .await;
    let active = activate(db, &rings()).await.unwrap();
    let mut failed = false;
    for _ in 0..100 {
        match step(db, &active, 1).await {
            Ok(p) => assert!(!p.complete),
            Err(Error::Verify | Error::Integrity { .. }) => {
                failed = true;
                break;
            }
            Err(other) => panic!("unexpected NULL failure: {other}"),
        }
    }
    assert!(failed);
}
#[tokio::test]
async fn sqlite_final_verification_refuses_required_null_seals() {
    null_review_case(&database().await, false).await;
    null_review_case(&database().await, true).await;
}
#[tokio::test]
async fn postgres_final_verification_refuses_required_null_seals() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_null_network").await
    else {
        return;
    };
    null_review_case(&f.conn, false).await;
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_null_seed").await
    else {
        return;
    };
    null_review_case(&f.conn, true).await;
}

async fn valid_null_review_case(db: &DatabaseConnection) {
    fixtures(db).await;
    exec(
        db,
        "UPDATE encryption_network_key SET state='deleted',sealed_seed=NULL",
        vec![],
    )
    .await;
    let parent = NetworkId::new(OWNER, "alpha").unwrap();
    let path = "docs/deterministic";
    let backend = LocalOneOfOneBackend::new(rings().seals);
    let public = backend
        .derive_named_public_key(
            &StaticSecret::from([31; 32]),
            &canonical_key_urn(&KeyLocation::new(&parent, path).unwrap()),
            None,
        )
        .unwrap();
    exec(db,"INSERT INTO encryption_network_key (network_id,key_path,kind,state,public_key,sealed_seed,key_version,created_at,updated_at) VALUES (?,?,'deterministic','active',?,NULL,1,'now','now')",vec![parent.to_string().into(),path.into(),public.into()]).await;
    let network = NetworkId::new(OWNER, "pending").unwrap().to_string();
    exec(db,"INSERT INTO encryption_network (network_id,owner_did,name,alg,key_version,public_key,state,threshold_n,threshold_t,key_backend,sealed_private_key,created_at,updated_at) VALUES (?,?,'pending','x25519-aes256gcm/v1',1,?,'pending',1,1,'local-one-of-one',NULL,'now','now')",vec![network.into(),OWNER.into(),Vec::<u8>::new().into()]).await;
    let active = activate(db, &rings()).await.unwrap();
    while !step(db, &active, 1).await.unwrap().complete {}
    assert!(progress(db).await.unwrap().verified > 0);
}
#[tokio::test]
async fn sqlite_schema_valid_nulls_complete() {
    valid_null_review_case(&database().await).await;
}
#[tokio::test]
async fn postgres_schema_valid_nulls_complete() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_valid_null").await
    else {
        return;
    };
    valid_null_review_case(&f.conn).await;
}

async fn verification_crash_and_alias_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let active = activate(db, &rings()).await.unwrap();
    while !step(db, &active, 1).await.unwrap().verifying {}
    // A failed verification page must not commit its cursor or checked count.
    assert!(step_page(db, &active, 2, Some(1)).await.is_err());
    assert_eq!(progress(db).await.unwrap().verified, 0);
    assert_eq!(step(db, &active, 1).await.unwrap().verified, 1);
    // A subsequent write invalidates that verified prefix and restarts the pass.
    exec(
        db,
        "UPDATE delegation_cid_alias SET canonical=?",
        vec![vec![0u8; 34].into()],
    )
    .await;
    assert_eq!(step(db, &active, 1).await.unwrap().verified, 1);
    let mut refused = false;
    for _ in 0..100 {
        match step(db, &active, 1).await {
            Ok(p) => assert!(!p.complete),
            Err(Error::Verify) => {
                refused = true;
                break;
            }
            Err(other) => panic!("unexpected alias verification failure: {other}"),
        }
    }
    assert!(refused);
    assert!(!progress(db).await.unwrap().complete);
}
#[tokio::test]
async fn sqlite_verification_crash_resume_and_alias_authentication() {
    verification_crash_and_alias_case(&database().await).await;
}
#[tokio::test]
async fn postgres_verification_crash_resume_and_alias_authentication() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_verify_crash").await
    else {
        return;
    };
    verification_crash_and_alias_case(&f.conn).await;
}

async fn early_write_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let overlap = rings();
    let bytes = overlap.webhooks.for_kid(2).unwrap().encrypt(
        b"hook",
        RowBinding::new("hook_subscription", "encrypted_secret", &[b"hook"]),
    );
    let update = || {
        bound(db.get_database_backend(),"UPDATE hook_subscription SET encrypted_secret=?,encrypted_secret_format=2 WHERE id='hook'",vec![bytes.clone().into()])
    };
    assert!(db.execute(update()).await.is_err());
    let active = activate(db, &overlap).await.unwrap();
    assert!(db.execute(update()).await.is_ok());
    while !step(db, &active, 1).await.unwrap().complete {}
}
#[tokio::test]
async fn sqlite_database_refuses_new_kid_before_fence() {
    early_write_case(&database().await).await;
}
#[tokio::test]
async fn postgres_database_refuses_new_kid_before_fence() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_early_write").await
    else {
        return;
    };
    early_write_case(&f.conn).await;
}
