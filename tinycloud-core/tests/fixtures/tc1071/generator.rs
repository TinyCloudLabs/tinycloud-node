// Copy this unchanged into f9d700bf's tinycloud-core/tests/tc1071_generate.rs,
// alongside fixtures/tc1071/support.rs. The output directory must be empty.
#[path = "fixtures/tc1071/support.rs"]
mod support;
use support::*;
use tinycloud_auth::{authorization::{HeaderEncode, TinyCloudDelegation}, resource::SpaceId};
use tinycloud_core::{encryption::ColumnEncryption, sea_orm::{EntityTrait, PaginatorTrait}, models::delegation};

#[tokio::test]
#[ignore = "Run only against unmodified f9d700bf to produce historical SQLite fixtures"]
async fn generate_historical_fixtures() {
    let output = std::path::PathBuf::from(std::env::var_os("TC1071_FIXTURE_OUTPUT").expect("set TC1071_FIXTURE_OUTPUT to an empty owned fixture directory"));
    std::fs::create_dir_all(&output).unwrap();
    let (_, _, issuer) = owner();
    let session_seed = 11;
    let child_seed = 12;
    let (jwk, audience, vm) = session(session_seed);
    let (child_jwk, _, child_vm) = session(child_seed);
    let mut fixtures = Vec::new();
    for (name, revoked_encoding, encrypted) in [
        ("revoked-v0", Some("v0"), false),
        ("revoked-v27", Some("v27"), false),
        ("active", None, false),
        ("encrypted-active", None, true),
    ] {
        let path = output.join(format!("{name}.sqlite"));
        assert!(!path.exists(), "never overwrite historical fixture {}", path.display());
        let db = open(&path).await.with_encryption(encrypted.then(|| ColumnEncryption::new(ENCRYPTION_KEY)));
        let resource = SpaceId::new(issuer.parse().unwrap(), name.parse().unwrap())
            .to_resource("kv".parse().unwrap(), None, None, None).to_string();
        let cacao = signed_cacao(&audience, Some(&resource), &format!("tc1071-{name}"));
        let canonical_header = TinyCloudDelegation::Cacao(Box::new(cacao.clone())).encode().unwrap();
        let mut rows = Vec::new();
        for (encoding, header) in variants(&cacao) {
            let raw_cid = cid(&header);
            // This assertion prevents inadvertently generating on fixed code.
            let parsed = tinycloud_core::events::Delegation::from_header_ser::<TinyCloudDelegation>(&header).unwrap();
            assert_eq!(parsed.content_hash().to_cid(0x55).to_string(), raw_cid, "generator must run on original f9d700bf decoder");
            register(&db, &header).await;
            assert_eq!(list(&db, &resource, &raw_cid, &jwk, &vm).await.unwrap(), Vec::<String>::new());
            let child_header = child_header(&resource, &raw_cid, session_seed, child_seed);
            let child_cid = cid(&child_header);
            register(&db, &child_header).await;
            assert_eq!(list(&db, &resource, &child_cid, &child_jwk, &child_vm).await.unwrap(), Vec::<String>::new());
            println!("TC1071 old {name} {} before revoke: root=kv/list-ok child=kv/list-ok raw={raw_cid}", encoding);
            rows.push(SignedRow { encoding, header, raw_cid: raw_cid.clone(), child_header, child_cid, child_proof_cid: raw_cid });
        }
        assert_eq!(delegation::Entity::find().count(db.connection()).await.unwrap(), (rows.len() * 2) as u64, "both historical root representations and all real children must be persisted");
        println!("TC1071 old {name}: persisted {} real delegations", rows.len() * 2);
        let revoked_raw_cid = revoked_encoding.map(|encoding| rows.iter().find(|row| row.encoding == encoding).unwrap().raw_cid.clone());
        let revocation_header = if let Some(target) = &revoked_raw_cid {
            let header = revoke(&db, target).await;
            for row in &rows {
                let accepted = list(&db, &resource, &row.raw_cid, &jwk, &vm).await;
                let child_accepted = list(&db, &resource, &row.child_cid, &child_jwk, &child_vm).await;
                println!("TC1071 old {name} {} after revoke {target}: root={} child={}", row.encoding, accepted.is_ok(), child_accepted.is_ok());
                if &row.raw_cid == target {
                    assert!(accepted.is_err());
                    assert!(child_accepted.is_err());
                } else {
                    assert!(accepted.is_ok(), "pre-fix equivalent {} must demonstrate authorization leak: {accepted:?}", row.encoding);
                    assert!(child_accepted.is_ok(), "pre-fix child of {} must demonstrate authorization leak: {child_accepted:?}", row.encoding);
                }
            }
            Some(header)
        } else { None };
        fixtures.push(Fixture {
            generated_by: "f9d700bf public SpaceDatabase::new/delegate/revoke/invoke".into(),
            database: format!("{name}.sqlite"), encrypted, issuer: issuer.clone(), resource,
            session_seed, child_seed, session_jwk: serde_json::to_value(&jwk).unwrap(), child_jwk: serde_json::to_value(&child_jwk).unwrap(),
            canonical_header, rows, revocation_header, revoked_raw_cid,
        });
        drop(db);
    }
    std::fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
}

#[tokio::test]
#[ignore = "Append the single-legacy-row control using unmodified f9d700bf only"]
async fn generate_single_historical_fixture() {
    let output = std::path::PathBuf::from(std::env::var_os("TC1071_FIXTURE_OUTPUT").unwrap());
    let mut fixtures: Vec<Fixture> = serde_json::from_slice(&std::fs::read(output.join("manifest.json")).unwrap()).unwrap();
    let database = "single-v0.sqlite";
    let path = output.join(database);
    assert!(!path.exists(), "never overwrite a historical fixture");
    let db = open(&path).await;
    let (_, _, issuer) = owner();
    let (jwk, audience, vm) = session(11);
    let (child_jwk, _, child_vm) = session(12);
    let resource = SpaceId::new(issuer.parse().unwrap(), "single-v0".parse().unwrap()).to_resource("kv".parse().unwrap(), None, None, None).to_string();
    let cacao = signed_cacao(&audience, Some(&resource), "tc1071-single-v0");
    let canonical_header = TinyCloudDelegation::Cacao(Box::new(cacao.clone())).encode().unwrap();
    let (encoding, header) = variants(&cacao).into_iter().find(|(encoding, _)| encoding == "v0").unwrap();
    let raw_cid = cid(&header);
    assert_eq!(tinycloud_core::events::Delegation::from_header_ser::<TinyCloudDelegation>(&header).unwrap().content_hash().to_cid(0x55).to_string(), raw_cid);
    register(&db, &header).await;
    let child_header = child_header(&resource, &raw_cid, 11, 12);
    let child_cid = cid(&child_header);
    register(&db, &child_header).await;
    assert_eq!(list(&db, &resource, &raw_cid, &jwk, &vm).await.unwrap(), Vec::<String>::new());
    assert_eq!(list(&db, &resource, &child_cid, &child_jwk, &child_vm).await.unwrap(), Vec::<String>::new());
    assert_eq!(delegation::Entity::find().count(db.connection()).await.unwrap(), 2);
    println!("TC1071 old single-v0: persisted 2 real delegations; root=kv/list-ok child=kv/list-ok raw={raw_cid}; canonical row absent");
    fixtures.push(Fixture {
        generated_by: "f9d700bf public SpaceDatabase::new/delegate/revoke/invoke".into(),
        database: database.into(), encrypted: false, issuer, resource,
        session_seed: 11, child_seed: 12, session_jwk: serde_json::to_value(&jwk).unwrap(), child_jwk: serde_json::to_value(&child_jwk).unwrap(),
        canonical_header, rows: vec![SignedRow { encoding, header, raw_cid: raw_cid.clone(), child_header, child_cid, child_proof_cid: raw_cid }],
        revocation_header: None, revoked_raw_cid: None,
    });
    drop(db);
    std::fs::write(output.join("manifest.json"), serde_json::to_vec_pretty(&fixtures).unwrap()).unwrap();
}
