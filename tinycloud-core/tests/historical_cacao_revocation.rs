#[path = "fixtures/tc1071/support.rs"]
mod support;
#[path = "fixtures/tc1071/upgrade_checks.rs"]
mod upgrade_checks;

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use rusqlite::types::Value as SqlValue;
use std::path::{Path, PathBuf};
use support::*;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudRevocation},
    ssi::jwk::JWK,
};
use tinycloud_core::{
    db::SpaceDatabase,
    events::Revocation,
    keys::StaticSecret,
    models::{delegation, revocation},
    relationships::parent_delegations,
    sea_orm::{
        ColumnTrait, ConnectionTrait, DbBackend, EntityTrait, PaginatorTrait, QueryFilter,
        Statement,
    },
    storage::memory::MemoryStore,
};

fn fixtures() -> Vec<Fixture> {
    let bytes = std::fs::read(fixture_dir().join("manifest.json")).expect("real f9d700bf fixture manifest must be checked in; generate it with fixtures/tc1071/generator.rs");
    let fixtures: Vec<Fixture> = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(fixtures.len(), 5);
    for fixture in &fixtures {
        assert_eq!(
            fixture.generated_by,
            "f9d700bf public SpaceDatabase::new/delegate/revoke/invoke"
        );
        assert_eq!(
            fixture.rows.len(),
            if fixture.database == "single-v0.sqlite" {
                1
            } else {
                6
            }
        );
        for row in &fixture.rows {
            assert_eq!(row.child_proof_cid, row.raw_cid);
        }
    }
    fixtures
}

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tc1071/generated")
}

fn copy_database(fixture: &Fixture) -> (tempfile::TempDir, PathBuf) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join(&fixture.database);
    std::fs::copy(fixture_dir().join(&fixture.database), &path).unwrap();
    (directory, path)
}

// Snapshot only immutable signed records and edges; new alias/migration rows
// and ordinary new invocation events are deliberately outside this snapshot.
fn signed_snapshot(path: &Path) -> Vec<Vec<Vec<SqlValue>>> {
    let db = rusqlite::Connection::open(path).unwrap();
    [
        "SELECT * FROM delegation ORDER BY id",
        "SELECT * FROM parent_delegation WHERE child IN (SELECT id FROM delegation) OR child IN (SELECT id FROM revocation) ORDER BY child, parent",
        "SELECT * FROM revocation ORDER BY id",
    ].into_iter().map(|sql| {
        let mut statement = db.prepare(sql).unwrap();
        let columns = statement.column_count();
        let rows = statement.query_map([], |row| (0..columns).map(|column| row.get::<_, SqlValue>(column)).collect::<rusqlite::Result<Vec<_>>>()).unwrap();
        rows.collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }).collect()
}

fn signers(fixture: &Fixture) -> (JWK, String, JWK, String) {
    let (session, _, session_vm) = session(fixture.session_seed);
    let (child, _, child_vm) = support::session(fixture.child_seed);
    assert_eq!(serde_json::to_value(&session).unwrap(), fixture.session_jwk);
    assert_eq!(serde_json::to_value(&child).unwrap(), fixture.child_jwk);
    (session, session_vm, child, child_vm)
}

async fn assert_signed_rows_untouched(db: &TestDb, fixture: &Fixture) {
    assert_eq!(
        delegation::Entity::find()
            .count(db.connection())
            .await
            .unwrap(),
        (fixture.rows.len() * 2) as u64
    );
    let encryption = fixture
        .encrypted
        .then(|| tinycloud_core::encryption::ColumnEncryption::new(ENCRYPTION_KEY));
    for row in &fixture.rows {
        let root = delegation::Entity::find_by_id(hash_from_cid(&row.raw_cid))
            .one(db.connection())
            .await
            .unwrap()
            .unwrap();
        let child = delegation::Entity::find_by_id(hash_from_cid(&row.child_cid))
            .one(db.connection())
            .await
            .unwrap()
            .unwrap();
        let root_bytes =
            tinycloud_core::encryption::maybe_decrypt(encryption.as_ref(), &root.serialization)
                .unwrap();
        assert_eq!(root_bytes, URL_SAFE.decode(&row.header).unwrap());
        let child_bytes =
            tinycloud_core::encryption::maybe_decrypt(encryption.as_ref(), &child.serialization)
                .unwrap();
        assert_eq!(child_bytes, row.child_header.as_bytes());
        let parents = parent_delegations::Entity::find()
            .filter(parent_delegations::Column::Child.eq(child.id))
            .all(db.connection())
            .await
            .unwrap();
        assert_eq!(parents.len(), 1);
        assert_eq!(parents[0].parent, hash_from_cid(&row.child_proof_cid));
        let (decoded, bytes) = TinyCloudDelegation::decode(&row.child_header).unwrap();
        assert_eq!(bytes, row.child_header.as_bytes());
        match decoded {
            TinyCloudDelegation::Ucan(ucan) => {
                assert_eq!(
                    ucan.payload().proof,
                    vec![row.child_proof_cid.parse().unwrap()]
                );
                assert_eq!(ucan.encode().unwrap(), row.child_header);
            }
            _ => panic!("historical child must remain its exact signed UCAN"),
        }
    }
    if let (Some(header), Some(target)) = (&fixture.revocation_header, &fixture.revoked_raw_cid) {
        let event = Revocation::from_header_ser::<TinyCloudRevocation>(header).unwrap();
        assert_eq!(event.0.revoked.to_string(), *target);
        let stored = revocation::Entity::find_by_id(event.content_hash())
            .one(db.connection())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.revoked, hash_from_cid(target));
        assert_eq!(stored.serialization, URL_SAFE.decode(header).unwrap());
    }
}

async fn assert_denied(db: &TestDb, fixture: &Fixture) {
    let (session, vm, child, child_vm) = signers(fixture);
    for row in &fixture.rows {
        let error = list(db, &fixture.resource, &row.raw_cid, &session, &vm)
            .await
            .expect_err(&format!(
                "historical equivalent {} still authorized after upgrade",
                row.encoding
            ));
        assert!(
            error.contains("delegation-revoked"),
            "reject for revocation, not unrelated failure: {error}"
        );
        let error = list(db, &fixture.resource, &row.child_cid, &child, &child_vm)
            .await
            .expect_err(&format!(
                "child citing historical {} root still authorized after upgrade",
                row.encoding
            ));
        assert!(
            error.contains("delegation-ancestor-revoked"),
            "child must reject for root revocation, not unrelated failure: {error}"
        );
        for id in [&row.raw_cid, &row.child_cid] {
            let status = db
                .delegation_status(hash_from_cid(id), &fixture.issuer, &[])
                .await
                .map_err(|error| error.to_string())
                .unwrap();
            assert_eq!(
                status,
                Some(tinycloud_core::db::DelegationStatus::Revoked),
                "status must agree with actual invocation rejection for {id}"
            );
        }
        println!("TC1071 upgraded {} {}: root={} rejected delegation-revoked; child={} rejected delegation-ancestor-revoked; owner status=revoked", fixture.database, row.encoding, row.raw_cid, row.child_cid);
    }
}

#[tokio::test]
async fn upgrade_revoked_historical_equivalents_reject_real_kv_list_both_directions() {
    for fixture in fixtures()
        .into_iter()
        .filter(|fixture| fixture.revoked_raw_cid.is_some())
    {
        let (_directory, path) = copy_database(&fixture);
        let before = signed_snapshot(&path);
        let db = open(&path).await;
        assert_signed_rows_untouched(&db, &fixture).await;
        assert_denied(&db, &fixture).await;
        for row in &fixture.rows {
            register(&db, &row.header).await;
        }
        assert_denied(&db, &fixture).await;
        assert_redelegation_denied(&db, &fixture).await;
        assert_eq!(
            signed_snapshot(&path),
            before,
            "upgrade and rejection must never rewrite signed historical records"
        );
    }
}

#[tokio::test]
async fn upgrade_active_legacy_children_remain_valid_until_owner_revokes_either_encoding() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.database == "active.sqlite")
        .unwrap();
    for encoding in [
        "v0",
        "v27",
        "map-order",
        "nonminimal",
        "null",
        "issuer-case",
    ] {
        let (_directory, path) = copy_database(&fixture);
        let before = signed_snapshot(&path);
        let db = open(&path).await;
        assert_signed_rows_untouched(&db, &fixture).await;
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
            "valid old signed proof references must survive startup unchanged"
        );
        let target = &fixture
            .rows
            .iter()
            .find(|row| row.encoding == encoding)
            .unwrap()
            .raw_cid;
        let header = revoke(&db, target).await;
        let signed = Revocation::from_header_ser::<TinyCloudRevocation>(&header).unwrap();
        assert_eq!(signed.0.revoked.to_string(), *target);
        assert_denied(&db, &fixture).await;
        for row in &fixture.rows {
            register(&db, &row.header).await;
        }
        assert_denied(&db, &fixture).await;
        assert_redelegation_denied(&db, &fixture).await;
        let after = signed_snapshot(&path);
        assert_eq!(
            before[..2],
            after[..2],
            "owner action must not rewrite roots or children"
        );
        drop(db);
        let db = open(&path).await;
        assert_denied(&db, &fixture).await;
    }
}

#[tokio::test]
async fn new_writes_deduplicate_equivalent_cacao_and_revoke_the_single_canonical_row() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.database == "active.sqlite")
        .unwrap();
    let (session, vm, _, _) = signers(&fixture);
    for encoding in ["v0", "v27"] {
        let directory = tempfile::tempdir().unwrap();
        let db = open(&directory.path().join("new.sqlite")).await;
        let canonical_cid = current_cid(&fixture.canonical_header);
        for row in &fixture.rows {
            assert_eq!(
                current_cid(&row.header),
                canonical_cid,
                "same current decode bytes must define equivalence: {}",
                row.encoding
            );
            let event = tinycloud_core::events::Delegation::from_header_ser::<TinyCloudDelegation>(
                &row.header,
            )
            .unwrap();
            let receipt = db
                .delegate(event)
                .await
                .map_err(|error| error.to_string())
                .unwrap();
            assert_eq!(
                receipt.delegation_cids,
                vec![hash_from_cid(&canonical_cid)],
                "public ingestion receipt must advertise the retained canonical CID"
            );
        }
        assert_eq!(
            delegation::Entity::find()
                .count(db.connection())
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            list(&db, &fixture.resource, &canonical_cid, &session, &vm)
                .await
                .unwrap(),
            Vec::<String>::new()
        );
        let alias_count = db
            .connection()
            .query_one(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT COUNT(*) AS n FROM delegation_cid_alias".to_owned(),
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get::<i64>("", "n")
            .unwrap();
        assert_eq!(alias_count, 1);
        let row = fixture
            .rows
            .iter()
            .find(|row| row.encoding == encoding)
            .unwrap();
        // New signatures target the CID the ingestion API actually retained.
        assert_eq!(current_cid(&row.header), canonical_cid);
        revoke(&db, &canonical_cid).await;
        let error = list(&db, &fixture.resource, &canonical_cid, &session, &vm)
            .await
            .unwrap_err();
        assert!(error.contains("delegation-revoked"), "{error}");
    }
}

#[tokio::test]
async fn encrypted_historical_rows_require_key_at_startup() {
    let fixture = fixtures()
        .into_iter()
        .find(|fixture| fixture.encrypted)
        .unwrap();
    let (_directory, path) = copy_database(&fixture);
    let before = signed_snapshot(&path);
    let result = SpaceDatabase::new(
        connection(&path).await,
        MemoryStore::default(),
        StaticSecret::new(vec![31; 32]).unwrap(),
    )
    .await;
    assert!(
        result.is_err(),
        "encrypted historical rows must fail boot without their decryption key"
    );
    assert_eq!(
        signed_snapshot(&path),
        before,
        "failed startup must not modify historical rows"
    );
}

fn reader_grant(fixture: &Fixture) -> (String, tinycloud_auth::resource::ResourceId) {
    use std::collections::BTreeMap;
    use tinycloud_auth::{
        cacaos::{
            siwe::Message,
            siwe_cacao::{Header, Signature, SiweCacao},
        },
        siwe_recap::{Ability, Capability},
    };
    let (_, audience, _) = session(fixture.session_seed);
    let resource = fixture
        .resource
        .parse::<tinycloud_auth::resource::ResourceId>()
        .unwrap()
        .space()
        .clone()
        .to_resource(
            "capabilities".parse().unwrap(),
            Some("all".parse().unwrap()),
            None,
            None,
        );
    let mut recap = Capability::<serde_json::Value>::new();
    recap.with_action(
        resource.as_uri(),
        "tinycloud.capabilities/read".parse::<Ability>().unwrap(),
        [BTreeMap::new()],
    );
    let message: Message = signed_cacao(&audience, None, "tc1071-query")
        .payload()
        .clone()
        .try_into()
        .unwrap();
    let message = recap.build_message(message).unwrap();
    let (key, _, _) = owner();
    let (signature, recovery) = key
        .sign_prehash_recoverable(&message.eip191_hash().unwrap())
        .unwrap();
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    let header = TinyCloudDelegation::Cacao(Box::new(SiweCacao::new(
        message.into(),
        Signature::from(bytes),
        Header,
    )))
    .encode()
    .unwrap();
    (header, resource)
}

async fn read_capabilities(
    db: &TestDb,
    fixture: &Fixture,
    resource: tinycloud_auth::resource::ResourceId,
    proof: &str,
    params: Option<serde_json::Value>,
) -> Vec<
    tinycloud_core::db::InvocationOutcome<
        <MemoryStore as tinycloud_core::storage::ImmutableReadStore>::Readable,
    >,
> {
    use tinycloud_auth::authorization::{make_invocation, InvocationOptions, TinyCloudInvocation};
    use tinycloud_core::{events::Invocation, storage::memory::MemoryStaging};
    let (jwk, _, vm) = session(fixture.session_seed);
    let header = make_invocation(
        [(resource, ["tinycloud.capabilities/read".parse().unwrap()])],
        &proof.parse().unwrap(),
        &jwk,
        &vm,
        EXPIRATION,
        InvocationOptions {
            facts: params.map(|params| vec![serde_json::json!({"capabilitiesReadParams": params})]),
            ..Default::default()
        },
    )
    .unwrap()
    .encode()
    .unwrap();
    let (_, outcomes) = db
        .invoke::<MemoryStaging>(
            Invocation::from_header_ser::<TinyCloudInvocation>(&header).unwrap(),
            Default::default(),
        )
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    assert_eq!(outcomes.len(), 1);
    outcomes
}

async fn assert_redelegation_denied(db: &TestDb, fixture: &Fixture) {
    use tinycloud_core::events::Delegation;
    for row in &fixture.rows {
        let direct = child_header(&fixture.resource, &row.raw_cid, fixture.session_seed, 13);
        let error = db
            .delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&direct).unwrap())
            .await
            .expect_err("revoked equivalent parent must not allow a new child")
            .to_string();
        assert!(error.contains("delegation-parent-revoked"), "{error}");
        let descendant = child_header(&fixture.resource, &row.child_cid, fixture.child_seed, 13);
        let error = db
            .delegate(Delegation::from_header_ser::<TinyCloudDelegation>(&descendant).unwrap())
            .await
            .expect_err("legacy child of revoked root must not allow a descendant")
            .to_string();
        assert!(error.contains("delegation-ancestor-revoked"), "{error}");
    }
}
