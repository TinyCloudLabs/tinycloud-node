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
// Test identities come from trusted creation inputs, never queried row fields.
fn trusted_document() -> manifest::Document {
    let mut rows = Vec::new();
    let backend = LocalOneOfOneBackend::new(rings().seals);
    for (name, byte) in [("alpha", 31), ("beta", 32)] {
        let network = NetworkId::new(OWNER, name).unwrap();
        rows.push(manifest::IdentityRow {
            kind: manifest::Kind::Network,
            network_id: network.to_string(),
            key_path: None,
            key_version: 1,
            public_key: hex::encode(PublicKey::from(&StaticSecret::from([byte; 32])).as_bytes()),
        });
        for path in ["apps/app/a", "apps/app/z"] {
            let location = KeyLocation::new(&network, path).unwrap();
            let public = backend
                .derive_named_public_key(
                    &StaticSecret::from([byte; 32]),
                    &canonical_key_urn(&location),
                    Some(&KeySeed::from_bytes([43; 32])),
                )
                .unwrap();
            rows.push(manifest::IdentityRow {
                kind: manifest::Kind::Seed,
                network_id: network.to_string(),
                key_path: Some(path.into()),
                key_version: 1,
                public_key: hex::encode(public),
            });
        }
    }
    rows.sort();
    manifest::Document {
        version: 1,
        provenance: manifest::Provenance {
            source_database: "tinycloud-node-production-usw".into(),
            backup_id: "test-backup".into(),
            snapshot_timestamp: "2026-01-01T00:00:00Z".into(),
            snapshot_sha256: crate::encryption_network::canonical::hash_hex(
                b"trusted test snapshot",
            ),
            exported_by: "test-custodian".into(),
            storage_location: "test-snapshot://fixture".into(),
            custody_record: "test-custody://record".into(),
        },
        rows,
    }
}
fn verify_document(mut document: manifest::Document) -> VerifiedManifest {
    document.rows.sort();
    let bytes = serde_json::to_vec(&document).unwrap();
    VerifiedManifest::verify(
        &bytes,
        &crate::encryption_network::canonical::hash_hex(&bytes),
    )
    .unwrap()
}
fn trusted_seed_identities() -> VerifiedManifest {
    verify_document(trusted_document())
}
fn empty_manifest() -> VerifiedManifest {
    let mut doc = trusted_document();
    doc.rows.clear();
    verify_document(doc)
}
fn seedless_manifest() -> VerifiedManifest {
    let mut doc = trusted_document();
    doc.rows.retain(|r| r.kind == manifest::Kind::Network);
    verify_document(doc)
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
        exec(db,"INSERT INTO encryption_ceremony (ceremony_id,network_id,kind,state,transcript_hash,started_at,completed_at) VALUES (?,?,'initial','completed',?,'now','now')",vec![format!("initial:{name}").into(),network.clone().into(),crate::encryption_network::canonical::hash_hex(PublicKey::from(&secret).as_bytes()).into()]).await;
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
    assert!(
        step_page(db, &rings, 2, &trusted_seed_identities(), Some(1))
            .await
            .is_err()
    );
    assert_eq!(progress(db).await.unwrap().rewritten, 0);
    assert_eq!(census(db).await.unwrap()[0].legacy, before[0].legacy);
    // A committed batch followed by process loss must resume from its cursor.
    assert!(
        !step(db, &rings, 1, &trusted_seed_identities())
            .await
            .unwrap()
            .complete
    );
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
        if step(db, &rings, 1, &trusted_seed_identities())
            .await
            .unwrap()
            .complete
        {
            break;
        }
    }
    let after = census(db).await.unwrap();
    assert!(after
        .iter()
        .all(|c| c.legacy == 0 && c.kids.keys().all(|k| *k == 2)));
    let done = progress(db).await.unwrap().rewritten;
    assert!(
        step(db, &rings, 10, &trusted_seed_identities())
            .await
            .unwrap()
            .complete
    );
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
        step(&db, &rings, 10, &trusted_seed_identities()).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(&db).await.unwrap().rewritten, 0);
    assert_eq!(census(&db).await.unwrap()[0].legacy, 2);
}

#[test]
fn serving_v2_kid0_seals_remain_compatible_and_v1_requires_migration() {
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
        .is_err());

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
        let page = step(db, &rings, 1, &trusted_seed_identities())
            .await
            .unwrap();
        if page.verifying {
            break;
        }
        assert!(!page.complete);
    }
    let first = step(db, &rings, 1, &trusted_seed_identities())
        .await
        .unwrap();
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
        match step(db, &rings, 1, &trusted_seed_identities()).await {
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
        match step(db, &rings, 1, &trusted_seed_identities()).await {
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
    while !step(db, &active, 1, &trusted_seed_identities())
        .await
        .unwrap()
        .complete
    {}
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
        match step(db, &active, 1, &trusted_seed_identities()).await {
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
    while !step(db, &active, 1, &trusted_seed_identities())
        .await
        .unwrap()
        .complete
    {}
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
    while !step(db, &active, 1, &trusted_seed_identities())
        .await
        .unwrap()
        .verifying
    {}
    // A failed verification page must not commit its cursor or checked count.
    assert!(
        step_page(db, &active, 2, &trusted_seed_identities(), Some(1))
            .await
            .is_err()
    );
    assert_eq!(progress(db).await.unwrap().verified, 0);
    assert_eq!(
        step(db, &active, 1, &trusted_seed_identities())
            .await
            .unwrap()
            .verified,
        1
    );
    // A subsequent write invalidates that verified prefix and restarts the pass.
    exec(
        db,
        "UPDATE delegation_cid_alias SET canonical=?",
        vec![vec![0u8; 34].into()],
    )
    .await;
    assert_eq!(
        step(db, &active, 1, &trusted_seed_identities())
            .await
            .unwrap()
            .verified,
        1
    );
    let mut refused = false;
    for _ in 0..100 {
        match step(db, &active, 1, &trusted_seed_identities()).await {
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
    while !step(db, &active, 1, &trusted_seed_identities())
        .await
        .unwrap()
        .complete
    {}
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

async fn serving_v1_refusal_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let backend = LocalOneOfOneBackend::new(rings().seals);
    let net = select_batch(db, COLUMNS[0], None, 1)
        .await
        .unwrap()
        .remove(0);
    let Key::Text(id) = net.key else {
        panic!("network key type");
    };
    assert!(backend
        .open_network_secret(
            net.blob.as_deref().unwrap(),
            &id,
            net.public_key.as_deref().unwrap()
        )
        .is_err());
    let seed = select_batch(db, COLUMNS[1], None, 1)
        .await
        .unwrap()
        .remove(0);
    let Key::Pair(id, path) = seed.key else {
        panic!("seed key type");
    };
    assert!(backend
        .open_seed(seed.blob.as_deref().unwrap(), &id, &path)
        .is_err());
}
#[tokio::test]
async fn sqlite_serving_v1_refusal() {
    serving_v1_refusal_case(&database().await).await;
}
#[tokio::test]
async fn postgres_serving_v1_refusal() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_serving_v1").await
    else {
        return;
    };
    serving_v1_refusal_case(&f.conn).await;
}
async fn legacy_network_evidence_case(db: &DatabaseConnection, variant: &str) {
    fixtures(db).await;
    exec(db, "DELETE FROM encryption_ceremony", vec![]).await;
    let network = NetworkId::new(OWNER, "alpha").unwrap().to_string();
    let original = StaticSecret::from([31; 32]);
    let expected =
        crate::encryption_network::canonical::hash_hex(PublicKey::from(&original).as_bytes());
    if variant != "missing" {
        exec(db,"INSERT INTO encryption_ceremony (ceremony_id,network_id,kind,state,transcript_hash,started_at,completed_at) VALUES ('witness',?,'initial','completed',?,'now','now')",vec![network.clone().into(),expected.clone().into()]).await;
    }
    match variant {
        "transplant" => {
            let replacement = StaticSecret::from([32; 32]);
            exec(db,"UPDATE encryption_network SET public_key=?,sealed_private_key=? WHERE network_id=?",vec![PublicKey::from(&replacement).as_bytes().to_vec().into(),ColumnEncryption::new([9;32]).encrypt_legacy(replacement.as_bytes()).into(),network.clone().into()]).await;
        }
        "multiple" | "conflicting" => {
            let digest = if variant == "multiple" {
                expected
            } else {
                "different".into()
            };
            exec(db,"INSERT INTO encryption_ceremony (ceremony_id,network_id,kind,state,transcript_hash,started_at,completed_at) VALUES ('duplicate',?,'initial','completed',?,'now','now')",vec![network.clone().into(),digest.into()]).await;
        }
        "incomplete" => {
            exec(db,"UPDATE encryption_ceremony SET state='started',completed_at=NULL WHERE network_id=?",vec![network.clone().into()]).await;
        }
        "mismatch" => {
            exec(
                db,
                "UPDATE encryption_ceremony SET transcript_hash='different' WHERE network_id=?",
                vec![network.clone().into()],
            )
            .await;
        }
        _ => {}
    }
    let active = activate(db, &rings()).await.unwrap();
    assert!(matches!(
        step(db, &active, 1, &trusted_seed_identities()).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(db).await.unwrap().rewritten, 0);
    assert_eq!(census(db).await.unwrap()[0].legacy, 2);
}
#[tokio::test]
async fn sqlite_legacy_network_evidence_rejects_transplant() {
    legacy_network_evidence_case(&database().await, "transplant").await;
}
#[tokio::test]
async fn postgres_legacy_network_evidence_rejects_transplant() {
    let Some(f) =
        crate::test_support::PostgresTestSchema::new("postgres_rekey_ceremony_transplant").await
    else {
        return;
    };
    legacy_network_evidence_case(&f.conn, "transplant").await;
}
async fn missing_legacy_seed_witness_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let active = activate(db, &rings()).await.unwrap();
    // Commit both network rewrites and advance to the seed page.
    assert!(step(db, &active, 2, &seedless_manifest()).await.is_ok());
    assert!(step(db, &active, 2, &seedless_manifest()).await.is_ok());
    let checkpoint = progress(db).await.unwrap().rewritten;
    assert!(matches!(
        step(db, &active, 2, &seedless_manifest()).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(db).await.unwrap().rewritten, checkpoint);
    assert!(!progress(db).await.unwrap().complete);
    assert_eq!(census(db).await.unwrap()[1].legacy, 4);
}
#[tokio::test]
async fn sqlite_legacy_seed_requires_external_witness() {
    missing_legacy_seed_witness_case(&database().await).await;
}
#[tokio::test]
async fn postgres_legacy_seed_requires_external_witness() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_rekey_seed_witness").await
    else {
        return;
    };
    missing_legacy_seed_witness_case(&f.conn).await;
}

#[tokio::test]
async fn sqlite_legacy_network_requires_unique_completed_ceremony() {
    for variant in [
        "missing",
        "multiple",
        "conflicting",
        "incomplete",
        "mismatch",
    ] {
        legacy_network_evidence_case(&database().await, variant).await;
    }
}
#[tokio::test]
async fn postgres_legacy_network_requires_unique_completed_ceremony() {
    for variant in [
        "missing",
        "multiple",
        "conflicting",
        "incomplete",
        "mismatch",
    ] {
        let Some(f) =
            crate::test_support::PostgresTestSchema::new("postgres_rekey_ceremony_evidence").await
        else {
            return;
        };
        legacy_network_evidence_case(&f.conn, variant).await;
    }
}

async fn supplied_seed_witness_case(db: &DatabaseConnection, variant: &str) {
    fixtures(db).await;
    let mut document = trusted_document();
    let network = NetworkId::new(OWNER, "alpha").unwrap();
    let path = "apps/app/a";
    if variant == "mismatch" {
        document
            .rows
            .iter_mut()
            .find(|r| {
                r.kind == manifest::Kind::Seed
                    && r.network_id == network.to_string()
                    && r.key_path.as_deref() == Some(path)
            })
            .unwrap()
            .public_key = hex::encode([0; 32]);
    } else if variant == "transplant" {
        let backend = LocalOneOfOneBackend::new(rings().seals);
        let public = backend
            .derive_named_public_key(
                &StaticSecret::from([31; 32]),
                &canonical_key_urn(&KeyLocation::new(&network, path).unwrap()),
                Some(&KeySeed::from_bytes([44; 32])),
            )
            .unwrap();
        exec(db,"UPDATE encryption_network_key SET public_key=?,sealed_seed=? WHERE network_id=? AND key_path=?",vec![public.into(),ColumnEncryption::new([9;32]).encrypt_legacy(&[44;32]).into(),network.to_string().into(),path.into()]).await;
    }
    let trusted = verify_document(document);
    let active = activate(db, &rings()).await.unwrap();
    assert!(step(db, &active, 2, &trusted).await.is_ok());
    assert!(step(db, &active, 2, &trusted).await.is_ok());
    let checkpoint = progress(db).await.unwrap().rewritten;
    if variant != "valid" {
        let before = select_batch(db, COLUMNS[1], None, 1)
            .await
            .unwrap()
            .remove(0)
            .blob;
        assert!(matches!(
            step(db, &active, 1, &trusted).await,
            Err(Error::Integrity { .. })
        ));
        assert!(
            select_batch(db, COLUMNS[1], None, 1)
                .await
                .unwrap()
                .remove(0)
                .blob
                == before
        );
        assert_eq!(progress(db).await.unwrap().rewritten, checkpoint);
        assert!(!progress(db).await.unwrap().complete);
        assert_eq!(census(db).await.unwrap()[1].legacy, 4);
    } else {
        while !step(db, &active, 1, &trusted).await.unwrap().complete {}
        assert!(census(db)
            .await
            .unwrap()
            .iter()
            .all(|c| c.legacy == 0 && c.kids.keys().all(|kid| *kid == 2)));
    }
}

#[tokio::test]
async fn sqlite_legacy_seed_trusted_external_witness_completes() {
    supplied_seed_witness_case(&database().await, "valid").await;
}

#[tokio::test]
async fn postgres_legacy_seed_trusted_external_witness_completes() {
    let Some(f) =
        crate::test_support::PostgresTestSchema::new("postgres_rekey_seed_valid_witness").await
    else {
        return;
    };
    supplied_seed_witness_case(&f.conn, "valid").await;
}

#[tokio::test]
async fn sqlite_legacy_seed_external_witness_rejects_mismatch_and_transplant() {
    for variant in ["mismatch", "transplant"] {
        supplied_seed_witness_case(&database().await, variant).await;
    }
}

#[tokio::test]
async fn postgres_legacy_seed_external_witness_rejects_mismatch_and_transplant() {
    for variant in ["mismatch", "transplant"] {
        let Some(f) =
            crate::test_support::PostgresTestSchema::new("postgres_rekey_seed_invalid_witness")
                .await
        else {
            return;
        };
        supplied_seed_witness_case(&f.conn, variant).await;
    }
}

async fn forged_ceremony_case(db: &DatabaseConnection) {
    fixtures(db).await;
    exec(db, "DELETE FROM encryption_network_key", vec![]).await;
    let network = NetworkId::new(OWNER, "alpha").unwrap().to_string();
    let copied = StaticSecret::from([32; 32]);
    let public = PublicKey::from(&copied);
    exec(
        db,
        "UPDATE encryption_network SET public_key=?,sealed_private_key=? WHERE network_id=?",
        vec![
            public.as_bytes().to_vec().into(),
            ColumnEncryption::new([9; 32])
                .encrypt_legacy(copied.as_bytes())
                .into(),
            network.clone().into(),
        ],
    )
    .await;
    exec(
        db,
        "UPDATE encryption_ceremony SET transcript_hash=? WHERE network_id=?",
        vec![
            crate::encryption_network::canonical::hash_hex(public.as_bytes()).into(),
            network.into(),
        ],
    )
    .await;
    let active = activate(db, &rings()).await.unwrap();
    let mut blocked = false;
    for _ in 0..100 {
        match step(db, &active, 1, &trusted_seed_identities()).await {
            Err(Error::Integrity { .. }) => {
                blocked = true;
                break;
            }
            Ok(page) => assert!(!page.complete),
            Err(other) => panic!("unexpected migration failure: {other}"),
        }
    }
    assert!(blocked);
    assert_eq!(progress(db).await.unwrap().rewritten, 0);
    assert_eq!(census(db).await.unwrap()[0].legacy, 2);
}

#[tokio::test]
async fn cond_sqlite_forged_ceremony_cannot_authorize_network_transplant() {
    forged_ceremony_case(&database().await).await;
}

#[tokio::test]
async fn cond_postgres_forged_ceremony_cannot_authorize_network_transplant() {
    let Some(f) =
        crate::test_support::PostgresTestSchema::new("postgres_rekey_forged_ceremony").await
    else {
        return;
    };
    forged_ceremony_case(&f.conn).await;
}

async fn absent_network_witness_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let active = activate(db, &rings()).await.unwrap();
    assert!(matches!(
        step(db, &active, 1, &empty_manifest()).await,
        Err(Error::Integrity { .. })
    ));
    assert_eq!(progress(db).await.unwrap().rewritten, 0);
    assert_eq!(census(db).await.unwrap()[0].legacy, 2);
}

#[tokio::test]
async fn cond_sqlite_network_requires_external_witness() {
    absent_network_witness_case(&database().await).await;
}

#[tokio::test]
async fn cond_postgres_network_requires_external_witness() {
    let Some(f) =
        crate::test_support::PostgresTestSchema::new("postgres_rekey_absent_network_witness").await
    else {
        return;
    };
    absent_network_witness_case(&f.conn).await;
}

#[test]
fn manifest_requires_pinned_hash_date_custody_and_canonical_encoding() {
    let document = trusted_document();
    let bytes = serde_json::to_vec(&document).unwrap();
    let hash = crate::encryption_network::canonical::hash_hex(&bytes);
    assert!(VerifiedManifest::verify(&bytes, &hash).is_ok());
    assert!(VerifiedManifest::verify(&bytes, &"00".repeat(32)).is_err());
    let pretty = serde_json::to_vec_pretty(&document).unwrap();
    assert!(VerifiedManifest::verify(
        &pretty,
        &crate::encryption_network::canonical::hash_hex(&pretty)
    )
    .is_err());
    for variant in 0..10 {
        let mut doc = document.clone();
        match variant {
            0 => doc.provenance.custody_record.clear(),
            1 => doc.provenance.exported_by.clear(),
            2 => doc.provenance.snapshot_timestamp = "not-a-date".into(),
            3 => doc.provenance.snapshot_timestamp = "9999-01-01T00:00:00Z".into(),
            4 => doc.provenance.snapshot_sha256 = "wrong".into(),
            5 => doc.provenance.backup_id.clear(),
            6 => doc.provenance.storage_location.clear(),
            7 => {
                doc.rows.push(doc.rows[0].clone());
                doc.rows.sort();
            }
            8 => doc.rows.reverse(),
            _ => doc.provenance.source_database = "other".into(),
        }
        let bytes = serde_json::to_vec(&doc).unwrap();
        assert!(VerifiedManifest::verify(
            &bytes,
            &crate::encryption_network::canonical::hash_hex(&bytes)
        )
        .is_err());
    }
}

fn manifest_test_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("tc2713-manifest-")
        .tempdir()
        .unwrap()
}

async fn manifest_runner_case(db: &DatabaseConnection) {
    fixtures(db).await;
    let dir = manifest_test_dir();
    let path = dir.path().join("manifest.json");
    let bytes = serde_json::to_vec(&trusted_document()).unwrap();
    let pin = crate::encryption_network::canonical::hash_hex(&bytes);
    std::fs::write(&path, &bytes).unwrap();
    assert!(matches!(
        manifest::run_offline(db, &rings(), &path, &"00".repeat(32), 1).await,
        Err(Error::Manifest)
    ));
    let target = || {
        bound(
            db.get_database_backend(),
            "SELECT target FROM storage_rekey WHERE id=1",
            vec![],
        )
    };
    assert!(matches!(
        manifest::run_offline(db, &rings(), &path, &pin, 0).await,
        Err(Error::Checkpoint)
    ));
    assert_eq!(
        db.query_one(target())
            .await
            .unwrap()
            .unwrap()
            .try_get::<i32>("", "target")
            .unwrap(),
        0
    );
    let mut absent = trusted_document();
    absent.rows.clear();
    let bytes = serde_json::to_vec(&absent).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    match manifest::run_offline(
        db,
        &rings(),
        &path,
        &crate::encryption_network::canonical::hash_hex(&bytes),
        1,
    )
    .await
    {
        Err(Error::ManifestCoverage(c)) => {
            assert_eq!(c.missing_networks, 2);
            assert_eq!(c.missing_seeds, 4);
        }
        _ => panic!("missing identities must be a blocking category"),
    }
    assert_eq!(
        db.query_one(target())
            .await
            .unwrap()
            .unwrap()
            .try_get::<i32>("", "target")
            .unwrap(),
        0
    );
    let bytes = serde_json::to_vec(&trusted_document()).unwrap();
    std::fs::write(&path, &bytes).unwrap();
    let network = NetworkId::new(OWNER, "alpha").unwrap();
    let new_path = "docs/after-snapshot";
    let public = LocalOneOfOneBackend::new(rings().seals)
        .derive_named_public_key(
            &StaticSecret::from([31; 32]),
            &canonical_key_urn(&KeyLocation::new(&network, new_path).unwrap()),
            None,
        )
        .unwrap();
    exec(db,"INSERT INTO encryption_network_key (network_id,key_path,kind,state,public_key,sealed_seed,key_version,created_at,updated_at) VALUES (?,?,'deterministic','active',?,NULL,1,'now','now')",vec![network.to_string().into(),new_path.into(),public.into()]).await;
    match manifest::run_offline(db, &rings(), &path, &pin, 1).await {
        Err(Error::ManifestCoverage(c)) => assert_eq!(c.missing_seeds, 1),
        _ => panic!("post-snapshot identities must block, including keys with no seed"),
    }
    assert_eq!(
        db.query_one(target())
            .await
            .unwrap()
            .unwrap()
            .try_get::<i32>("", "target")
            .unwrap(),
        0
    );
    exec(
        db,
        "DELETE FROM encryption_network_key WHERE network_id=? AND key_path=?",
        vec![network.to_string().into(), new_path.into()],
    )
    .await;
    let beta = NetworkId::new(OWNER, "beta").unwrap().to_string();
    exec(db,"UPDATE encryption_network SET public_key=?,sealed_private_key=NULL,state='pending' WHERE network_id=?",vec![Vec::<u8>::new().into(),beta.clone().into()]).await;
    match manifest::run_offline(db, &rings(), &path, &pin, 1).await {
        Err(Error::ManifestCoverage(c)) => assert_eq!(c.mismatched_networks, 1),
        _ => panic!("an allocated snapshot identity cannot become an ignored pending row"),
    }
    let secret = StaticSecret::from([32; 32]);
    exec(db,"UPDATE encryption_network SET public_key=?,sealed_private_key=?,state='active' WHERE network_id=?",vec![PublicKey::from(&secret).as_bytes().to_vec().into(),ColumnEncryption::new([9;32]).encrypt_legacy(secret.as_bytes()).into(),beta.into()]).await;
    assert!(
        manifest::run_offline(db, &rings(), &path, &pin, 1)
            .await
            .unwrap()
            .complete
    );
}

#[tokio::test]
async fn sqlite_manifest_runner_checks_proof_before_fencing_and_completes() {
    manifest_runner_case(&database().await).await;
}

async fn manifest_snapshot_network_case(db: &DatabaseConnection, version_changed: bool) {
    fixtures(db).await;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("manifest.json");
    let bytes = serde_json::to_vec(&trusted_document()).unwrap();
    let pin = crate::encryption_network::canonical::hash_hex(&bytes);
    std::fs::write(&path, bytes).unwrap();
    let beta = NetworkId::new(OWNER, "beta").unwrap().to_string();
    exec(
        db,
        "DELETE FROM encryption_network_key WHERE network_id=?",
        vec![beta.clone().into()],
    )
    .await;
    if version_changed {
        exec(db,"UPDATE encryption_network SET key_version=7,public_key=?,sealed_private_key=NULL,state='pending' WHERE network_id=?",vec![Vec::<u8>::new().into(),beta.into()]).await;
    } else {
        exec(db,"UPDATE encryption_network SET sealed_private_key=NULL,state='pending' WHERE network_id=?",vec![beta.into()]).await;
    }
    let counts = manifest::coverage(db, &trusted_seed_identities())
        .await
        .unwrap();
    assert!(
        counts.blocked(),
        "snapshot network identity and seal must remain present at the pinned version"
    );
    assert!(matches!(
        manifest::run_offline(db, &rings(), &path, &pin, 1).await,
        Err(Error::ManifestCoverage(_))
    ));
    let row = db
        .query_one(bound(
            db.get_database_backend(),
            "SELECT target,rewritten FROM storage_rekey WHERE id=1",
            vec![],
        ))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(row.try_get::<i32>("", "target").unwrap(), 0);
    assert_eq!(row.try_get::<i64>("", "rewritten").unwrap(), 0);
}

#[tokio::test]
async fn sqlite_manifest_snapshot_version_mutation_blocks_before_fence() {
    manifest_snapshot_network_case(&database().await, true).await;
}

#[tokio::test]
async fn postgres_manifest_snapshot_version_mutation_blocks_before_fence() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("manifest_snapshot_version").await
    else {
        return;
    };
    manifest_snapshot_network_case(&f.conn, true).await;
}

#[tokio::test]
async fn sqlite_manifest_snapshot_missing_seal_blocks_before_fence() {
    manifest_snapshot_network_case(&database().await, false).await;
}

#[tokio::test]
async fn postgres_manifest_snapshot_missing_seal_blocks_before_fence() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("manifest_snapshot_seal").await
    else {
        return;
    };
    manifest_snapshot_network_case(&f.conn, false).await;
}

#[tokio::test]
async fn postgres_manifest_runner_checks_proof_before_fencing_and_completes() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_manifest_runner").await
    else {
        return;
    };
    manifest_runner_case(&f.conn).await;
}

async fn exporter_case(db: &DatabaseConnection, postgres: bool) {
    let dir = manifest_test_dir();
    let archive = dir.path().join("snapshot.dump");
    let output = dir.path().join("manifest.json");
    let file_db = if postgres {
        None
    } else {
        let db = Database::connect(format!("sqlite:{}?mode=rwc", archive.display()))
            .await
            .unwrap();
        crate::migrations::Migrator::up(&db, None).await.unwrap();
        Some(db)
    };
    let db = file_db.as_ref().unwrap_or(db);
    fixtures(db).await;
    let mut command = std::process::Command::new("python3");
    command.arg(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../tools/export-rekey-manifest.py"
    ));
    if postgres {
        let url = crate::test_support::postgres_test_url("manifest_exporter").unwrap();
        let schema: String = db
            .query_one(bound(
                db.get_database_backend(),
                "SELECT current_schema() AS schema",
                vec![],
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get("", "schema")
            .unwrap();
        let result = std::process::Command::new("pg_dump")
            .args([
                "--no-password",
                "--dbname",
                &url,
                "--schema",
                &schema,
                "--file",
            ])
            .arg(&archive)
            .env("PGPASSFILE", "/dev/null")
            .env_remove("PGHOSTADDR")
            .env_remove("PGSERVICE")
            .env_remove("PGSERVICEFILE")
            .env("PGOPTIONS", "-c default_transaction_read_only=on")
            .output()
            .unwrap();
        assert!(result.status.success(), "test snapshot export failed");
        command.args(["--restored-postgres-url", &url, "--schema", &schema]);
    } else {
        db.query_one(bound(
            db.get_database_backend(),
            "PRAGMA wal_checkpoint(TRUNCATE)",
            vec![],
        ))
        .await
        .unwrap();
        command.arg("--sqlite-snapshot").arg(&archive);
    }
    let result = command
        .arg("--snapshot-file")
        .arg(&archive)
        .args([
            "--backup-id",
            "test-backup",
            "--snapshot-timestamp",
            "2026-01-01T00:00:00Z",
            "--exported-by",
            "test-custodian",
            "--storage-location",
            "test-snapshot://archive",
            "--custody-record",
            "test-custody://record",
            "--output",
        ])
        .arg(&output)
        .output()
        .unwrap();
    assert!(result.status.success(), "read-only manifest export failed");
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report.as_object().unwrap().len(), 3);
    let proof =
        VerifiedManifest::load(&output, report["manifest_sha256"].as_str().unwrap()).unwrap();
    assert_eq!(proof.counts(), (2, 4));
    assert!(!manifest::coverage(db, &proof).await.unwrap().blocked());
    assert_eq!(census(db).await.unwrap()[0].legacy, 2);
    let bytes = std::fs::read(&output).unwrap();
    let doc: manifest::Document = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        doc.provenance.snapshot_sha256,
        crate::encryption_network::canonical::hash_hex(&std::fs::read(&archive).unwrap())
    );
}

#[tokio::test]
async fn sqlite_read_only_snapshot_export_is_canonical_and_loadable() {
    exporter_case(&database().await, false).await;
}

#[tokio::test]
async fn postgres_read_only_snapshot_export_is_canonical_and_loadable() {
    let Some(f) = crate::test_support::PostgresTestSchema::new("postgres_manifest_export").await
    else {
        return;
    };
    exporter_case(&f.conn, true).await;
}
