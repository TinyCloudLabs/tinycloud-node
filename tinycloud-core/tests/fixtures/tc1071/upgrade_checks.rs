use super::*;
use sea_orm_migration::{MigrationTrait, MigratorTrait};
use tinycloud_core::{
    db::InvocationOutcome, encryption::ColumnEncryption, events::Delegation, hash::hash,
};

fn assert_aliases(path: &Path, fixture: &Fixture) {
    let connection = rusqlite::Connection::open(path).unwrap();
    let count: i64 = connection
        .query_row("SELECT COUNT(*) FROM delegation_cid_alias", [], |row| {
            row.get(0)
        })
        .unwrap();
    assert_eq!(
        count,
        (fixture.rows.len() * 2) as i64,
        "every real persisted CACAO and UCAN needs an alias"
    );
    for row in &fixture.rows {
        for (raw, canonical) in [
            (&row.raw_cid, current_cid(&row.header)),
            (&row.child_cid, row.child_cid.clone()),
        ] {
            let id: Vec<u8> = hash_from_cid(raw).into();
            let canonical_bytes: Vec<u8> = connection
                .query_row(
                    "SELECT canonical FROM delegation_cid_alias WHERE id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(
                canonical_bytes,
                Vec::<u8>::from(hash_from_cid(&canonical)),
                "alias must use exactly the current ingestion decoder bytes"
            );
        }
    }
}

struct BeforeAliasMigrator;

#[async_trait::async_trait]
impl MigratorTrait for BeforeAliasMigrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        tinycloud_core::migrations::Migrator::migrations()
            .into_iter()
            .filter(|migration| migration.name() != "m20261014_000000_delegation_cid_alias")
            .collect()
    }
}

#[tokio::test]
async fn later_schema_upgrade_preserves_revoked_historical_grants() {
    for fixture in fixtures().into_iter().filter(|fixture| {
        matches!(
            fixture.database.as_str(),
            "revoked-v0.sqlite" | "revoked-v27.sqlite"
        )
    }) {
        let (_directory, path) = copy_database(&fixture);
        let before = signed_snapshot(&path);
        let connection = connection(&path).await;
        BeforeAliasMigrator::up(&connection, None).await.unwrap();
        assert!(
            connection
                .query_one(Statement::from_string(
                    DbBackend::Sqlite,
                    "SELECT version FROM seaql_migrations WHERE version = 'm20261015_000000_delegation_cursor_index'".to_string(),
                ))
                .await
                .unwrap()
                .is_some(),
            "exercise an already-applied later migration before alias backfill"
        );
        drop(connection);

        let db = open(&path).await;
        assert_eq!(signed_snapshot(&path), before);
        assert_signed_rows_untouched(&db, &fixture).await;
        assert_aliases(&path, &fixture);
        assert_denied(&db, &fixture).await;
        for row in &fixture.rows {
            register(&db, &row.header).await;
        }
        assert_denied(&db, &fixture).await;
        drop(db);
        let db = open(&path).await;
        assert_denied(&db, &fixture).await;
    }
}

#[tokio::test]
async fn encrypted_boot_decrypts_exact_historical_records_and_preserves_revocation_equivalence() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.encrypted)
        .unwrap();
    let (_directory, path) = copy_database(&fixture);
    let before = signed_snapshot(&path);
    let failed = SpaceDatabase::new_with_encryption(
        connection(&path).await,
        MemoryStore::default(),
        StaticSecret::new(vec![31; 32]).unwrap(),
        Some(ColumnEncryption::new([44; 32])),
    )
    .await;
    assert!(
        failed.is_err(),
        "wrong encryption key must fail boot, never skip encrypted rows"
    );
    assert_eq!(signed_snapshot(&path), before);
    let db = SpaceDatabase::new_with_encryption(
        connection(&path).await,
        MemoryStore::default(),
        StaticSecret::new(vec![31; 32]).unwrap(),
        Some(ColumnEncryption::new(ENCRYPTION_KEY)),
    )
    .await
    .unwrap();
    assert_signed_rows_untouched(&db, &fixture).await;
    assert_aliases(&path, &fixture);
    let (session, vm, child, child_vm) = signers(&fixture);
    for row in &fixture.rows {
        assert_eq!(
            list(&db, &fixture.resource, &row.raw_cid, &session, &vm)
                .await
                .unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            list(&db, &fixture.resource, &row.child_cid, &child, &child_vm)
                .await
                .unwrap(),
            Vec::<String>::new()
        );
    }
    assert_eq!(
        signed_snapshot(&path),
        before,
        "decrypting at boot must not reencrypt or rewrite signed records"
    );
    let target = &fixture
        .rows
        .iter()
        .find(|row| row.encoding == "v0")
        .unwrap()
        .raw_cid;
    revoke(&db, target).await;
    assert_denied(&db, &fixture).await;
    let after = signed_snapshot(&path);
    assert_eq!(before[..2], after[..2]);
    drop(db);
    let db = SpaceDatabase::new_with_encryption(
        connection(&path).await,
        MemoryStore::default(),
        StaticSecret::new(vec![31; 32]).unwrap(),
        Some(ColumnEncryption::new(ENCRYPTION_KEY)),
    )
    .await
    .unwrap();
    assert_denied(&db, &fixture).await;
    assert_aliases(&path, &fixture);
}

fn assert_raw(event: &Delegation, header: &str, advertised_cid: &str) {
    let expected = if header.contains('.') {
        header.as_bytes().to_vec()
    } else {
        URL_SAFE.decode(header).unwrap()
    };
    assert_eq!(
        event.serialized_bytes(),
        expected,
        "API must return the exact historically signed encoding"
    );
    assert_eq!(
        event.content_hash().to_cid(0x55).to_string(),
        advertised_cid,
        "advertised CID must hash the returned raw bytes, never re-encoded normalized CACAO"
    );
    let returned_header = if header.contains('.') {
        String::from_utf8(event.serialized_bytes().to_vec()).unwrap()
    } else {
        URL_SAFE.encode(event.serialized_bytes())
    };
    assert_eq!(returned_header, header);
    assert_eq!(
        hash(event.serialized_bytes()),
        hash_from_cid(advertised_cid)
    );
}

#[tokio::test]
async fn upgraded_list_and_chain_return_exact_historical_raw_headers_for_advertised_cids() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.database == "active.sqlite")
        .unwrap();
    let (_directory, path) = copy_database(&fixture);
    let db = open(&path).await;
    assert_aliases(&path, &fixture);
    let (reader, resource) = reader_grant(&fixture);
    let proof = current_cid(&reader);
    register(&db, &reader).await;
    let before = signed_snapshot(&path);
    // Both the legacy parameter-free surface and the explicit list variant
    // must retain raw bytes alongside their advertised persisted IDs.
    for params in [
        None,
        Some(serde_json::json!({"type":"list","filters":{"direction":"all"}})),
    ] {
        let outcomes = read_capabilities(&db, &fixture, resource.clone(), &proof, params).await;
        let InvocationOutcome::OpenSessions(sessions) = outcomes.into_iter().next().unwrap() else {
            panic!("expected actual capabilities list outcome")
        };
        for row in &fixture.rows {
            assert_raw(
                sessions
                    .get(&hash_from_cid(&row.raw_cid))
                    .expect("legacy root advertised"),
                &row.header,
                &row.raw_cid,
            );
            let child = sessions
                .get(&hash_from_cid(&row.child_cid))
                .expect("legacy child advertised");
            assert_raw(child, &row.child_header, &row.child_cid);
            assert_eq!(child.0.parents, vec![row.child_proof_cid.parse().unwrap()]);
        }
    }
    for row in &fixture.rows {
        let outcomes = read_capabilities(
            &db,
            &fixture,
            resource.clone(),
            &proof,
            Some(serde_json::json!({"type":"chain","delegation_cid":row.child_cid})),
        )
        .await;
        let InvocationOutcome::DelegationChain(chain) = outcomes.into_iter().next().unwrap() else {
            panic!("expected actual capabilities chain outcome")
        };
        assert_eq!(chain.len(), 2);
        assert_raw(&chain[0], &row.child_header, &row.child_cid);
        assert_raw(&chain[1], &row.header, &row.raw_cid);
        assert_eq!(
            chain[0].0.parents,
            vec![row.child_proof_cid.parse().unwrap()]
        );
    }
    assert_eq!(
        signed_snapshot(&path),
        before,
        "list and chain are read-only for immutable signed records and edges"
    );
    let target = &fixture
        .rows
        .iter()
        .find(|row| row.encoding == "v0")
        .unwrap()
        .raw_cid;
    revoke(&db, target).await;
    assert_denied(&db, &fixture).await;
    for params in [
        None,
        Some(serde_json::json!({"type":"list","filters":{"direction":"all"}})),
    ] {
        let outcomes = read_capabilities(&db, &fixture, resource.clone(), &proof, params).await;
        let InvocationOutcome::OpenSessions(sessions) = outcomes.into_iter().next().unwrap() else {
            panic!("expected actual capabilities list outcome")
        };
        assert!(
            sessions.contains_key(&hash_from_cid(&proof)),
            "independent authorized reader grant remains active"
        );
        for row in &fixture.rows {
            assert!(
                !sessions.contains_key(&hash_from_cid(&row.raw_cid)),
                "list must hide equivalent revoked roots"
            );
            let outcomes = read_capabilities(
                &db,
                &fixture,
                resource.clone(),
                &proof,
                Some(serde_json::json!({"type":"chain","delegation_cid":row.child_cid})),
            )
            .await;
            let InvocationOutcome::DelegationChain(chain) = outcomes.into_iter().next().unwrap()
            else {
                panic!("expected actual capabilities chain outcome")
            };
            for returned in chain {
                assert!(
                    fixture
                        .rows
                        .iter()
                        .all(|root| returned.content_hash() != hash_from_cid(&root.raw_cid)),
                    "chain must not advertise an equivalent revoked root"
                );
                assert_raw(&returned, &row.child_header, &row.child_cid);
            }
        }
    }
    println!("TC1071 upgraded active: default+filtered capabilities lists and all six chains preserve exact raw-header/CID correspondence; exclude equivalent revoked roots; independent reader grant remains authorized");
}

#[tokio::test]
async fn single_legacy_root_without_canonical_row_survives_import_then_revokes_as_one_identity() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.database == "single-v0.sqlite")
        .unwrap();
    let (_directory, path) = copy_database(&fixture);
    let before = signed_snapshot(&path);
    let db = open(&path).await;
    assert_signed_rows_untouched(&db, &fixture).await;
    assert_aliases(&path, &fixture);
    let canonical = current_cid(&fixture.canonical_header);
    assert!(
        delegation::Entity::find_by_id(hash_from_cid(&canonical))
            .one(db.connection())
            .await
            .unwrap()
            .is_none(),
        "canonical key must not require an existing delegation row"
    );
    let row = &fixture.rows[0];
    let (session, vm, child, child_vm) = signers(&fixture);
    assert_eq!(
        list(&db, &fixture.resource, &row.raw_cid, &session, &vm)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        list(&db, &fixture.resource, &row.child_cid, &child, &child_vm)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(signed_snapshot(&path), before);
    register(&db, &fixture.canonical_header).await;
    assert_eq!(
        list(&db, &fixture.resource, &canonical, &session, &vm)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
    assert_eq!(
        list(&db, &fixture.resource, &row.child_cid, &child, &child_vm)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
    let header = revoke(&db, &row.raw_cid).await;
    let signed = Revocation::from_header_ser::<TinyCloudRevocation>(&header).unwrap();
    assert_eq!(signed.0.revoked.to_string(), row.raw_cid);
    assert_denied(&db, &fixture).await;
    register(&db, &row.header).await;
    register(&db, &fixture.canonical_header).await;
    let error = list(&db, &fixture.resource, &canonical, &session, &vm)
        .await
        .unwrap_err();
    assert!(error.contains("delegation-revoked"), "{error}");
    assert_denied(&db, &fixture).await;
    assert_redelegation_denied(&db, &fixture).await;
    assert_eq!(
        delegation::Entity::find()
            .count(db.connection())
            .await
            .unwrap(),
        3
    );
    let after = signed_snapshot(&path);
    for old_row in &before[0] {
        assert!(
            after[0].contains(old_row),
            "old signed delegation row must remain unchanged"
        );
    }
    assert_eq!(before[1], after[1]);
    println!("TC1071 upgraded single-v0: raw={} canonical={} old signed child={} preserved; canonical import and reimports cannot resurrect owner-revoked identity", row.raw_cid, canonical, row.child_cid);
}

#[tokio::test]
async fn list_and_chain_preserve_the_exact_signed_ucan_proof_cid() {
    use tinycloud_auth::authorization::Cid;
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.database == "active.sqlite")
        .unwrap();
    let (_directory, path) = copy_database(&fixture);
    let db = open(&path).await;
    let root = &fixture
        .rows
        .iter()
        .find(|row| row.encoding == "v0")
        .unwrap()
        .raw_cid;
    let root: Cid = root.parse().unwrap();
    // The graph stores hashes, but a signed proof is a complete CID. Changing
    // its codec during response projection would rewrite the signed reference.
    let signed_proof = Cid::new_v1(0x71, *root.hash());
    let header = child_header(
        &fixture.resource,
        &signed_proof.to_string(),
        fixture.session_seed,
        fixture.child_seed,
    );
    let child = cid(&header);
    register(&db, &header).await;
    let (reader, resource) = reader_grant(&fixture);
    let proof = current_cid(&reader);
    register(&db, &reader).await;
    let (_, _, child_key, child_vm) = signers(&fixture);
    assert_eq!(
        list(&db, &fixture.resource, &child, &child_key, &child_vm)
            .await
            .unwrap(),
        Vec::<String>::new()
    );
    let outcomes = read_capabilities(&db, &fixture, resource.clone(), &proof, None).await;
    let InvocationOutcome::OpenSessions(sessions) = outcomes.into_iter().next().unwrap() else {
        panic!("expected capabilities list")
    };
    let returned = sessions.get(&hash_from_cid(&child)).unwrap();
    assert_raw(returned, &header, &child);
    assert_eq!(returned.0.parents, vec![signed_proof]);
    let outcomes = read_capabilities(
        &db,
        &fixture,
        resource,
        &proof,
        Some(serde_json::json!({"type":"chain","delegation_cid":child})),
    )
    .await;
    let InvocationOutcome::DelegationChain(chain) = outcomes.into_iter().next().unwrap() else {
        panic!("expected capabilities chain")
    };
    assert_raw(&chain[0], &header, &child);
    assert_eq!(chain[0].0.parents, vec![signed_proof]);
    revoke(&db, &root.to_string()).await;
    let error = list(&db, &fixture.resource, &child, &child_key, &child_vm)
        .await
        .unwrap_err();
    assert!(error.contains("delegation-ancestor-revoked"), "{error}");
}
