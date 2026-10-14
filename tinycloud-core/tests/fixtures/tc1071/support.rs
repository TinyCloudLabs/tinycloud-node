#![allow(dead_code)]

use base64::{engine::general_purpose::URL_SAFE, Engine as _};
use k256::ecdsa::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use std::{
    collections::BTreeMap,
    sync::atomic::{AtomicU64, Ordering},
};
use tinycloud_auth::{
    authorization::{
        make_invocation, Cid, HeaderEncode, InvocationOptions, TinyCloudDelegation,
        TinyCloudInvocation, TinyCloudRevocation,
    },
    cacaos::{
        siwe::{Message, Version},
        siwe_cacao::{Header, Signature, SiweCacao},
    },
    ipld_core::ipld::Ipld,
    resolver::DID_METHODS,
    resource::ResourceId,
    siwe_recap::{Ability, Capability},
    ssi::{
        claims::jwt::NumericDate,
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
    ucan_capabilities_object::Capabilities,
};
use tinycloud_core::{
    db::{InvocationOutcome, SpaceDatabase},
    events::{Delegation, Invocation, Revocation},
    hash::{hash, Hash},
    keys::{public_key_to_did_key, Keypair, StaticSecret},
    sea_orm::{ConnectOptions, Database, DatabaseConnection},
    storage::memory::{MemoryStaging, MemoryStore},
};

pub type TestDb = SpaceDatabase<DatabaseConnection, MemoryStore, StaticSecret>;
pub const EXPIRATION: f64 = 4_102_444_800.0; // 2100-01-01
pub const OWNER_SEED: u8 = 7;
pub const ENCRYPTION_KEY: [u8; 32] = [43; 32];
static NONCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedRow {
    pub encoding: String,
    pub header: String,
    pub raw_cid: String,
    pub child_header: String,
    pub child_cid: String,
    pub child_proof_cid: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Fixture {
    pub generated_by: String,
    pub database: String,
    pub encrypted: bool,
    pub issuer: String,
    pub resource: String,
    pub session_seed: u8,
    pub child_seed: u8,
    pub session_jwk: Value,
    pub child_jwk: Value,
    pub canonical_header: String,
    pub rows: Vec<SignedRow>,
    pub revocation_header: Option<String>,
    pub revoked_raw_cid: Option<String>,
}

pub fn session(seed: u8) -> (JWK, String, String) {
    let key = Keypair::ed25519_from_bytes([seed; 32]).unwrap();
    let ed = key.clone().try_into_ed25519().unwrap();
    let did = public_key_to_did_key(key.public());
    let jwk: JWK = serde_json::from_value(serde_json::json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
        "x": URL_SAFE.encode(ed.public().to_bytes()).trim_end_matches('='),
        "d": URL_SAFE.encode([seed; 32]).trim_end_matches('='),
    }))
    .unwrap();
    assert_eq!(DID_METHODS.generate(&jwk, "key").unwrap().to_string(), did);
    let vm = format!("{did}#{}", did.trim_start_matches("did:key:"));
    (jwk, did, vm)
}

pub fn owner() -> (SigningKey, [u8; 20], String) {
    let key = SigningKey::from_bytes(&[OWNER_SEED; 32].into()).unwrap();
    let public = key.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = Keccak256::digest(&public.as_bytes()[1..])[12..]
        .try_into()
        .unwrap();
    let issuer = format!(
        "did:pkh:eip155:1:0x{}",
        tinycloud_auth::cacaos::siwe::encode_eip55(&address)
    );
    (key, address, issuer)
}

pub fn signed_cacao(audience: &str, resource: Option<&str>, nonce: &str) -> SiweCacao {
    let (key, address, _) = owner();
    let mut message = Message {
        scheme: Some("https".parse().unwrap()),
        domain: "tc1071.invalid".parse().unwrap(),
        address,
        statement: None,
        uri: audience.parse().unwrap(),
        version: Version::V1,
        chain_id: 1,
        nonce: nonce.into(),
        issued_at: "2020-01-01T00:00:00Z".parse().unwrap(),
        expiration_time: Some("2100-01-01T00:00:00Z".parse().unwrap()),
        not_before: None,
        request_id: None,
        resources: vec![],
    };
    if let Some(resource) = resource {
        let mut recap = Capability::<Value>::new();
        recap.with_action(
            resource.parse().unwrap(),
            "tinycloud.kv/list".parse::<Ability>().unwrap(),
            [BTreeMap::new()],
        );
        let owner_space = resource.replace("/kv", "/space");
        recap.with_action(
            owner_space.parse().unwrap(),
            "tinycloud.space/host".parse::<Ability>().unwrap(),
            [BTreeMap::new()],
        );
        message = recap.build_message(message).unwrap();
    }
    let (signature, recovery) = key
        .sign_prehash_recoverable(&message.eip191_hash().unwrap())
        .unwrap();
    let mut bytes = [0; 65];
    bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
    bytes[64] = u8::from(recovery) + 27;
    SiweCacao::new(message.into(), Signature::from(bytes), Header)
}

pub fn cid(header: &str) -> String {
    let bytes = if header.contains('.') {
        header.as_bytes().to_vec()
    } else {
        URL_SAFE.decode(header).unwrap()
    };
    hash(&bytes).to_cid(0x55).to_string()
}

pub fn current_cid(header: &str) -> String {
    let (_, bytes) = TinyCloudDelegation::decode(header).unwrap();
    hash(&bytes).to_cid(0x55).to_string()
}

pub fn variants(cacao: &SiweCacao) -> Vec<(String, String)> {
    let canonical_header = TinyCloudDelegation::Cacao(Box::new(cacao.clone()))
        .encode()
        .unwrap();
    let canonical = URL_SAFE.decode(canonical_header).unwrap();
    let value: Ipld = serde_ipld_dagcbor::from_slice(&canonical).unwrap();
    let mut result = vec![("v27".into(), URL_SAFE.encode(&canonical))];
    let mut v0 = value.clone();
    if let Ipld::Map(root) = &mut v0 {
        if let Ipld::Map(signature) = root.get_mut("s").unwrap() {
            if let Ipld::Bytes(bytes) = signature.get_mut("s").unwrap() {
                bytes[64] -= 27;
            } else {
                panic!("signature must be bytes");
            }
        }
    }
    result.push((
        "v0".into(),
        URL_SAFE.encode(serde_ipld_dagcbor::to_vec(&v0).unwrap()),
    ));
    // Encode the same three root entries in reverse DAG-CBOR order.
    if let Ipld::Map(root) = &value {
        let mut reordered = vec![0xa3];
        for key in ["s", "p", "h"] {
            reordered.extend(serde_ipld_dagcbor::to_vec(&key).unwrap());
            reordered.extend(serde_ipld_dagcbor::to_vec(root.get(key).unwrap()).unwrap());
        }
        result.push(("map-order".into(), URL_SAFE.encode(reordered)));
    }
    assert_eq!(canonical[0], 0xa3);
    let mut nonminimal = vec![0xb8, 0x03];
    nonminimal.extend_from_slice(&canonical[1..]);
    result.push(("nonminimal".into(), URL_SAFE.encode(nonminimal)));
    let mut null = value.clone();
    if let Ipld::Map(root) = &mut null {
        if let Ipld::Map(payload) = root.get_mut("p").unwrap() {
            payload.insert("nbf".into(), Ipld::Null);
        }
    }
    result.push((
        "null".into(),
        URL_SAFE.encode(serde_ipld_dagcbor::to_vec(&null).unwrap()),
    ));
    let mut lowercase = value;
    if let Ipld::Map(root) = &mut lowercase {
        if let Ipld::Map(payload) = root.get_mut("p").unwrap() {
            if let Ipld::String(issuer) = payload.get_mut("iss").unwrap() {
                *issuer = issuer.to_lowercase();
            }
        }
    }
    result.push((
        "issuer-case".into(),
        URL_SAFE.encode(serde_ipld_dagcbor::to_vec(&lowercase).unwrap()),
    ));
    result
}

pub fn child_header(resource: &str, proof: &str, session_seed: u8, child_seed: u8) -> String {
    let (jwk, _, vm) = session(session_seed);
    let (_, audience, _) = session(child_seed);
    let mut caps = Capabilities::<Value>::new();
    caps.with_action(
        resource.parse().unwrap(),
        "tinycloud.kv/list".parse::<Ability>().unwrap(),
        [BTreeMap::new()],
    );
    Payload::<Value> {
        issuer: vm.parse().unwrap(),
        audience: audience.parse().unwrap(),
        not_before: Some(NumericDate::try_from_seconds(1_577_836_800.0).unwrap()),
        expiration: NumericDate::try_from_seconds(EXPIRATION).unwrap(),
        nonce: Some(format!("tc1071-child-{proof}")),
        facts: None,
        proof: vec![proof.parse().unwrap()],
        attenuation: caps,
    }
    .sign(Algorithm::EdDSA, &jwk)
    .unwrap()
    .encode()
    .unwrap()
}

pub async fn connection(path: &std::path::Path) -> DatabaseConnection {
    Database::connect(
        ConnectOptions::new(format!("sqlite:{}?mode=rwc", path.display()))
            .max_connections(1)
            .to_owned(),
    )
    .await
    .unwrap()
}

pub async fn open(path: &std::path::Path) -> TestDb {
    SpaceDatabase::new(
        connection(path).await,
        MemoryStore::default(),
        StaticSecret::new(vec![31; 32]).unwrap(),
    )
    .await
    .unwrap()
}

pub async fn register(db: &TestDb, header: &str) {
    db.delegate(Delegation::from_header_ser::<TinyCloudDelegation>(header).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
}

pub async fn revoke(db: &TestDb, target: &str) -> String {
    let header = TinyCloudRevocation::Cacao(Box::new(signed_cacao(
        &format!("ucan:{target}"),
        None,
        "tc1071-owner-revoke",
    )))
    .encode()
    .unwrap();
    db.revoke(Revocation::from_header_ser::<TinyCloudRevocation>(&header).unwrap())
        .await
        .map_err(|error| error.to_string())
        .unwrap();
    header
}

pub async fn list(
    db: &TestDb,
    resource: &str,
    proof: &str,
    jwk: &JWK,
    vm: &str,
) -> Result<Vec<String>, String> {
    let invocation = make_invocation(
        [(
            format!("{resource}/").parse::<ResourceId>().unwrap(),
            ["tinycloud.kv/list".parse::<Ability>().unwrap()],
        )],
        &proof.parse::<Cid>().unwrap(),
        jwk,
        vm,
        EXPIRATION,
        InvocationOptions {
            nonce: Some(format!(
                "tc1071-{}-{}",
                std::process::id(),
                NONCE.fetch_add(1, Ordering::Relaxed)
            )),
            ..Default::default()
        },
    )
    .unwrap()
    .encode()
    .unwrap();
    let (_, outcomes) = db
        .invoke::<MemoryStaging>(
            Invocation::from_header_ser::<TinyCloudInvocation>(&invocation).unwrap(),
            Default::default(),
        )
        .await
        .map_err(|error| error.to_string())?;
    assert_eq!(outcomes.len(), 1, "kv/list must actually execute");
    match outcomes.into_iter().next().unwrap() {
        InvocationOutcome::KvList(keys, truncated, cursor) => {
            assert!(!truncated);
            assert!(cursor.is_none());
            Ok(keys.into_iter().map(|key| key.to_string()).collect())
        }
        other => panic!("expected actual kv/list result, got {other:?}"),
    }
}

pub fn hash_from_cid(value: &str) -> Hash {
    Hash::from(value.parse::<Cid>().unwrap())
}
