//! Owner-signed delete authorization: every binding has a refusal test that
//! names the refusal's own detail, so a check removed from the verifier fails
//! the test of that check and not only an adjacent one.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use sea_orm::{ConnectOptions, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{encode_eip55, Message, TimeStamp},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature},
    },
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    siwe_recap::Capability as Recap,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload as UcanPayload,
    },
    ucan_capabilities_object::Capabilities,
};

use super::{
    canonical::canonical_hash,
    delete_auth::{
        verify_owner_delete, DeleteTarget, VerifiedOwnerDelete, KEY_DELETE_URI_PREFIX,
        NONCE_RETENTION_SECS,
    },
    network_id::NetworkId,
    protocol::{KEY_ADMIN_TYPE, KEY_BLOCK_ACTION, KEY_DELETE_ACTION},
    service::{EncryptionService, EncryptionServiceError},
};
use crate::{encryption::ColumnEncryption, migrations::Migrator, models::encryption_nonce};

const NODE: &str = "did:key:z6MkNodeTest";
const OTHER_NODE: &str = "did:key:z6MkOtherNode";

// ------------------------------------------------------------------ wallet

struct Wallet {
    key: SigningKey,
    address: [u8; 20],
}

impl Wallet {
    fn new(seed: u8) -> Self {
        let key = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let public = key.verifying_key().to_encoded_point(false);
        let address = Keccak256::digest(&public.as_bytes()[1..])[12..]
            .try_into()
            .unwrap();
        Self { key, address }
    }

    fn did(&self) -> String {
        format!("did:pkh:eip155:1:0x{}", encode_eip55(&self.address))
    }

    fn sign(&self, message: &Message) -> Signature {
        let (signature, recovery) = self
            .key
            .sign_prehash_recoverable(&message.eip191_hash().unwrap())
            .unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        Signature::from(bytes)
    }
}

fn timestamp(unix: i64) -> TimeStamp {
    TimeStamp::from(OffsetDateTime::from_unix_timestamp(unix).unwrap())
}

fn proof_cid() -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(b"parent"))
}

/// Everything a SIWE owner delete is made of. `valid` yields an accepted
/// credential; a test changes the one field it exercises.
struct CacaoSpec<'a> {
    signer: &'a Wallet,
    /// The address written into the message, when it is not the signer's.
    claimed: Option<&'a Wallet>,
    recap: Vec<(String, Vec<&'static str>)>,
    caveat: bool,
    proof: bool,
    /// The statement the message carries. `None` derives it from the target.
    statement: Option<String>,
    uri: String,
    resources_before: Vec<String>,
    resources_after: Vec<String>,
    iat: i64,
    exp: Option<i64>,
    nbf: Option<i64>,
    nonce: String,
}

impl<'a> CacaoSpec<'a> {
    fn valid(signer: &'a Wallet, target: &DeleteTarget, now: i64) -> Self {
        Self {
            signer,
            claimed: None,
            recap: vec![(target.urn(), vec![KEY_DELETE_ACTION])],
            caveat: false,
            proof: false,
            statement: None,
            uri: format!("{KEY_DELETE_URI_PREFIX}{NODE}"),
            resources_before: vec![],
            resources_after: vec![],
            iat: now,
            exp: Some(now + 300),
            nbf: None,
            nonce: "nonce-0001".to_string(),
        }
    }

    fn header(&self, target: &DeleteTarget) -> String {
        let mut recap = Recap::<Value>::default();
        for (urn, abilities) in &self.recap {
            for ability in abilities {
                let nb = if self.caveat {
                    vec![BTreeMap::from([("x".to_string(), json!(1))])]
                } else {
                    vec![]
                };
                recap
                    .with_action_convert(urn.as_str(), *ability, nb)
                    .unwrap();
            }
        }
        if self.proof {
            recap = recap.with_proof(&proof_cid());
        }
        let lead = if target.is_prefix() {
            format!("Delete all TinyCloud keys under {}.", target.urn())
        } else {
            format!("Delete the TinyCloud key {}.", target.urn())
        };
        let address = self.claimed.unwrap_or(self.signer).address;
        let mut message = recap
            .build_message(Message {
                scheme: None,
                domain: "example.com".parse().unwrap(),
                address,
                statement: Some(lead),
                uri: self.uri.parse().unwrap(),
                version: tinycloud_auth::cacaos::siwe::Version::V1,
                chain_id: 1,
                nonce: self.nonce.clone(),
                issued_at: timestamp(self.iat),
                expiration_time: self.exp.map(timestamp),
                not_before: self.nbf.map(timestamp),
                request_id: None,
                resources: self
                    .resources_before
                    .iter()
                    .map(|r| r.parse().unwrap())
                    .collect(),
            })
            .unwrap();
        message
            .resources
            .extend(self.resources_after.iter().map(|r| r.parse().unwrap()));
        if let Some(statement) = &self.statement {
            message.statement = Some(statement.clone());
        }
        let signature = self.signer.sign(&message);
        let cacao = CacaoPayload::from(message).sign::<Eip191>(signature);
        TinyCloudDelegation::Cacao(Box::new(cacao))
            .encode()
            .unwrap()
    }
}

// -------------------------------------------------------------------- ucan

struct UcanSpec<'a> {
    signer: &'a JWK,
    /// The issuer DID URL the invocation claims.
    issuer_vm: String,
    audience: String,
    caps: Vec<(String, String)>,
    caveat: bool,
    facts: Vec<Value>,
    proof: Vec<Cid>,
    exp: i64,
    nbf: Option<i64>,
    nonce: Option<String>,
}

fn did_key() -> (JWK, String, String) {
    let mut jwk = JWK::generate_ed25519().unwrap();
    jwk.algorithm = Some(Algorithm::EdDSA);
    let mut vm = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let did = vm.clone();
    let fragment = vm.rsplit_once(':').unwrap().1.to_string();
    vm.push('#');
    vm.push_str(&fragment);
    (jwk, did, vm)
}

fn admin_facts(network: &NetworkId, target: &DeleteTarget, body: &Value) -> Value {
    json!({
        "type": KEY_ADMIN_TYPE,
        "targetNode": NODE,
        "networkId": network.to_string(),
        "keyPath": target.key_path(),
        "action": KEY_DELETE_ACTION,
        "bodyHash": canonical_hash(body),
    })
}

impl<'a> UcanSpec<'a> {
    fn valid(
        signer: &'a JWK,
        vm: &str,
        network: &NetworkId,
        target: &DeleteTarget,
        body: &Value,
        now: i64,
    ) -> Self {
        Self {
            signer,
            issuer_vm: vm.to_string(),
            audience: NODE.to_string(),
            caps: vec![(target.urn(), KEY_DELETE_ACTION.to_string())],
            caveat: false,
            facts: vec![admin_facts(network, target, body)],
            proof: vec![],
            exp: now + 300,
            nbf: Some(now),
            nonce: Some("urn:uuid:nonce-0001".to_string()),
        }
    }

    fn header(&self) -> String {
        let mut capabilities = Capabilities::new();
        for (uri, ability) in &self.caps {
            let nb = if self.caveat {
                BTreeMap::from([("x".to_string(), json!(1))])
            } else {
                BTreeMap::new()
            };
            capabilities.with_action(
                uri.parse().unwrap(),
                ability
                    .parse::<tinycloud_auth::ucan_capabilities_object::Ability>()
                    .unwrap(),
                [nb],
            );
        }
        UcanPayload {
            issuer: self.issuer_vm.parse::<DIDURLBuf>().unwrap(),
            audience: self.audience.parse::<DIDBuf>().unwrap(),
            not_before: self
                .nbf
                .map(|t| NumericDate::try_from_seconds(t as f64).unwrap()),
            expiration: NumericDate::try_from_seconds(self.exp as f64).unwrap(),
            nonce: self.nonce.clone(),
            facts: Some(self.facts.clone()),
            proof: self.proof.clone(),
            attenuation: capabilities,
        }
        .sign(Algorithm::EdDSA, self.signer)
        .unwrap()
        .encode()
        .unwrap()
    }
}

// ------------------------------------------------------------------ helpers

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn pkh_network(wallet: &Wallet) -> NetworkId {
    NetworkId::new(wallet.did(), "default".to_string()).unwrap()
}

fn prefix_target(network: &NetworkId, id: &str) -> DeleteTarget {
    DeleteTarget::parse(network, &format!("apps/{id}/")).unwrap()
}

fn key_target(network: &NetworkId, path: &str) -> DeleteTarget {
    DeleteTarget::parse(network, path).unwrap()
}

fn body_for(target: &DeleteTarget) -> Value {
    json!({ "keyPath": target.key_path() })
}

async fn verify(
    header: &str,
    network: &NetworkId,
    target: &DeleteTarget,
    body: &Value,
    at: i64,
) -> Result<VerifiedOwnerDelete, EncryptionServiceError> {
    verify_owner_delete(header, NODE, network, target, body, at).await
}

/// Asserts `OwnerOnly` whose detail contains `fragment`.
fn assert_refused(result: Result<VerifiedOwnerDelete, EncryptionServiceError>, fragment: &str) {
    match result {
        Err(EncryptionServiceError::OwnerOnly(detail)) => assert!(
            detail.contains(fragment),
            "refused for another reason: {detail} (wanted {fragment})"
        ),
        other => panic!("expected owner_only containing {fragment:?}, got {other:?}"),
    }
}

// ------------------------------------------------------------------ targets

#[test]
fn delete_target_parses_one_key_and_exact_app_prefixes_only() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let key = DeleteTarget::parse(&network, "secrets/x").unwrap();
    assert!(!key.is_prefix());
    assert_eq!(key.key_path(), "secrets/x");
    assert!(key.urn().ends_with(":default/secrets/x"));

    let prefix = DeleteTarget::parse(&network, "apps/foo/").unwrap();
    assert!(prefix.is_prefix());
    assert_eq!(prefix.key_path(), "apps/foo/");
    assert!(prefix.urn().ends_with(":default/apps/foo/"));

    for refused in [
        "apps/",
        "apps//",
        "apps/foo/x/",
        "apps/foo//",
        "secrets/",
        "secrets/x/",
        "appsx/y/",
        "apps.x/y/",
        "apps/Foo/",
        "/",
        "",
        "apps/foo:bar/",
    ] {
        assert!(
            matches!(
                DeleteTarget::parse(&network, refused),
                Err(EncryptionServiceError::KeyPathInvalid(_))
            ),
            "{refused:?} must be refused"
        );
    }
}

#[test]
fn delete_prefix_follows_the_shared_vectors() {
    #[derive(serde::Deserialize)]
    struct Vectors {
        #[serde(rename = "appIdValid")]
        app_ids: Vec<AppId>,
        #[serde(rename = "deletePrefix")]
        delete_prefix: Vec<DeletePrefix>,
    }
    #[derive(serde::Deserialize)]
    struct AppId {
        id: String,
        valid: bool,
    }
    #[derive(serde::Deserialize)]
    struct DeletePrefix {
        prefix: String,
        accepted: bool,
    }
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../tests/fixtures/encryption/app-key-vectors.json"
    ))
    .unwrap();
    let network = pkh_network(&Wallet::new(1));
    for case in vectors.delete_prefix {
        // Without a trailing slash the path is a key delete and `apps/foo` is
        // not a key.
        assert_eq!(
            DeleteTarget::parse(&network, &case.prefix).is_ok(),
            case.accepted,
            "{:?}",
            case.prefix
        );
    }
    for case in vectors.app_ids {
        let parsed = DeleteTarget::parse(&network, &format!("apps/{}/", case.id));
        assert_eq!(parsed.is_ok(), case.valid, "app id {:?}", case.id);
    }
}

#[test]
fn delete_statements_match_the_shared_vectors_exactly() {
    #[derive(serde::Deserialize)]
    struct Vectors {
        #[serde(rename = "deleteUriPrefix")]
        uri_prefix: String,
        #[serde(rename = "deleteStatements")]
        statements: Vec<Statement>,
    }
    #[derive(serde::Deserialize)]
    struct Statement {
        owner: String,
        network: String,
        #[serde(rename = "keyPath")]
        key_path: String,
        statement: String,
    }
    let vectors: Vectors = serde_json::from_str(include_str!(
        "../../tests/fixtures/encryption/app-key-vectors.json"
    ))
    .unwrap();
    assert_eq!(vectors.uri_prefix, KEY_DELETE_URI_PREFIX);
    assert_eq!(vectors.statements.len(), 2, "one prefix and one key vector");
    for case in vectors.statements {
        let network = NetworkId::new(case.owner, case.network).unwrap();
        let target = DeleteTarget::parse(&network, &case.key_path).unwrap();
        assert_eq!(target.siwe_statement().unwrap(), case.statement);
    }
}

#[tokio::test]
async fn a_request_network_other_than_the_targets_is_refused() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let other = NetworkId::new(wallet.did(), "other".to_string()).unwrap();
    let target = prefix_target(&network, "foo");
    let at = now();
    let header = CacaoSpec::valid(&wallet, &target, at).header(&target);
    assert_refused(
        verify(&header, &other, &target, &body_for(&target), at).await,
        "the target's network",
    );
}

// ----------------------------------------------------------- CACAO: accepted

#[tokio::test]
async fn cacao_owner_prefix_delete_is_accepted() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let target = prefix_target(&network, "foo");
    let at = now();
    let header = CacaoSpec::valid(&wallet, &target, at).header(&target);
    let verified = verify(&header, &network, &target, &body_for(&target), at)
        .await
        .unwrap();
    assert_eq!(verified.owner, wallet.did());
    assert_eq!(verified.nonce, "nonce-0001");
    assert_eq!(verified.exp, at + 300);
    assert!(verified.auth_cid.starts_with("bafk"));
}

#[tokio::test]
async fn cacao_owner_key_delete_is_accepted() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let target = key_target(&network, "apps/foo/token");
    let at = now();
    let header = CacaoSpec::valid(&wallet, &target, at).header(&target);
    verify(&header, &network, &target, &body_for(&target), at)
        .await
        .unwrap();
}

// ---------------------------------------------------------- CACAO: refusals

#[tokio::test]
async fn cacao_signed_by_another_wallet_is_refused() {
    let owner = Wallet::new(1);
    let other = Wallet::new(2);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    // Another wallet signs and states its own address: valid signature, wrong signer.
    let header = CacaoSpec::valid(&other, &target, at).header(&target);
    assert_refused(
        verify(&header, &network, &target, &body_for(&target), at).await,
        "signer is not the network owner",
    );
}

#[tokio::test]
async fn cacao_with_the_owner_address_and_another_signature_is_refused() {
    let owner = Wallet::new(1);
    let other = Wallet::new(2);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    let mut spec = CacaoSpec::valid(&other, &target, at);
    spec.claimed = Some(&owner);
    assert_refused(
        verify(
            &spec.header(&target),
            &network,
            &target,
            &body_for(&target),
            at,
        )
        .await,
        "SIWE signature is invalid",
    );
}

#[tokio::test]
async fn cacao_for_another_prefix_is_refused() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    for (urn, label) in [
        (prefix_target(&network, "bar").urn(), "sibling prefix"),
        (prefix_target(&network, "foo.bar").urn(), "longer id"),
        (key_target(&network, "apps/foo/x").urn(), "a key under it"),
        // The same path without its trailing slash names a key.
        (
            target.urn().strip_suffix('/').unwrap().to_string(),
            "no trailing slash",
        ),
    ] {
        let mut spec = CacaoSpec::valid(&owner, &target, at);
        spec.recap = vec![(urn, vec![KEY_DELETE_ACTION])];
        let result = verify(
            &spec.header(&target),
            &network,
            &target,
            &body_for(&target),
            at,
        )
        .await;
        assert!(
            matches!(&result, Err(EncryptionServiceError::OwnerOnly(_))),
            "{label}: {result:?}"
        );
    }
}

#[tokio::test]
async fn cacao_recap_must_equal_the_url_network_and_body_path() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let other_network = NetworkId::new(owner.did(), "other".to_string()).unwrap();
    let signed_target = prefix_target(&network, "foo");
    let at = now();
    let header = CacaoSpec::valid(&owner, &signed_target, at).header(&signed_target);

    // Same credential, URL names another network.
    let url_target = prefix_target(&other_network, "foo");
    assert_refused(
        verify(
            &header,
            &other_network,
            &url_target,
            &body_for(&url_target),
            at,
        )
        .await,
        "ReCap is not key.delete on exactly the requested target",
    );
    // Same credential, body names another prefix.
    let body_target = prefix_target(&network, "bar");
    assert_refused(
        verify(&header, &network, &body_target, &body_for(&body_target), at).await,
        "ReCap is not key.delete on exactly the requested target",
    );
    // Same credential, body names a key.
    let key = key_target(&network, "apps/foo/x");
    assert_refused(
        verify(&header, &network, &key, &body_for(&key), at).await,
        "ReCap is not key.delete on exactly the requested target",
    );
}

#[tokio::test]
async fn cacao_ability_and_recap_shape_are_exact() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    let body = body_for(&target);

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.recap = vec![(target.urn(), vec![KEY_BLOCK_ACTION])];
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "not key.delete on exactly the requested target",
    );

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.recap = vec![(target.urn(), vec![KEY_DELETE_ACTION, KEY_BLOCK_ACTION])];
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "exactly one ability",
    );

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.recap.push((
        prefix_target(&network, "bar").urn(),
        vec![KEY_DELETE_ACTION],
    ));
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "exactly one resource",
    );

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.caveat = true;
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "carries caveats",
    );

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.proof = true;
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "cites no proofs",
    );
}

#[tokio::test]
async fn cacao_resources_are_the_recap_only() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    let body = body_for(&target);

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.resources_before = vec!["https://example.com/".to_string()];
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "exactly one resource",
    );

    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.resources_after = vec!["https://example.com/".to_string()];
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "exactly one resource",
    );

    // No ReCap at all: only a plain resource.
    let mut spec = CacaoSpec::valid(&owner, &target, at);
    spec.recap = vec![];
    spec.resources_before = vec!["https://example.com/".to_string()];
    assert_refused(
        verify(&spec.header(&target), &network, &target, &body, at).await,
        "not a ReCap",
    );
}

#[tokio::test]
async fn cacao_uri_must_name_this_node() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    for uri in [
        format!("{KEY_DELETE_URI_PREFIX}{OTHER_NODE}"),
        format!("urn:tinycloud:encryption:{NODE}"),
        NODE.to_string(),
    ] {
        let mut spec = CacaoSpec::valid(&owner, &target, at);
        spec.uri = uri.clone();
        assert_refused(
            verify(
                &spec.header(&target),
                &network,
                &target,
                &body_for(&target),
                at,
            )
            .await,
            "uri does not name this node",
        );
    }
}

#[tokio::test]
async fn cacao_statement_must_state_the_delete() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    let recap_text = {
        // The honest statement, to derive wrong ones from.
        let spec = CacaoSpec::valid(&owner, &target, at);
        let header = spec.header(&target);
        let (TinyCloudDelegation::Cacao(cacao), _) = TinyCloudDelegation::decode(&header).unwrap()
        else {
            panic!("cacao")
        };
        cacao.payload().statement.clone().unwrap()
    };
    let lead = format!("Delete all TinyCloud keys under {}.", target.urn());
    let recap_sentence = recap_text
        .strip_prefix(&format!("{lead} "))
        .unwrap()
        .to_string();
    for statement in [
        // Another prefix in the lead sentence.
        format!(
            "Delete all TinyCloud keys under {}. {recap_sentence}",
            prefix_target(&network, "bar").urn()
        ),
        // The per-key wording on a prefix.
        format!(
            "Delete the TinyCloud key {}. {recap_sentence}",
            target.urn()
        ),
        // No lead sentence.
        recap_sentence.clone(),
        // Trailing text.
        format!("{recap_text} Also something else."),
        // Doubled separator.
        format!("{lead}  {recap_sentence}"),
    ] {
        let mut spec = CacaoSpec::valid(&owner, &target, at);
        spec.statement = Some(statement.clone());
        assert_refused(
            verify(
                &spec.header(&target),
                &network,
                &target,
                &body_for(&target),
                at,
            )
            .await,
            "statement",
        );
    }
}

#[tokio::test]
async fn cacao_lifetime_follows_the_one_rule() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    let body = body_for(&target);
    let run = |mutate: &dyn Fn(&mut CacaoSpec)| {
        let mut spec = CacaoSpec::valid(&owner, &target, at);
        mutate(&mut spec);
        spec.header(&target)
    };

    // exp - iat = 300 is the longest accepted lifetime.
    let header = run(&|s| {
        s.iat = at;
        s.exp = Some(at + 300);
    });
    verify(&header, &network, &target, &body, at).await.unwrap();
    // 301 is refused.
    let header = run(&|s| s.exp = Some(at + 301));
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "lifetime exceeds 300 seconds",
    );
    // A long lifetime stays refused when `now` is late in it.
    let header = run(&|s| {
        s.iat = at - 3000;
        s.exp = Some(at + 100);
    });
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "lifetime exceeds 300 seconds",
    );
    // now < exp: at exp it is expired.
    let header = run(&|s| {
        s.iat = at - 100;
        s.exp = Some(at);
    });
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "expired",
    );
    // One second before exp it is accepted.
    verify(&header, &network, &target, &body, at - 1)
        .await
        .unwrap();
    // No expiration.
    let header = run(&|s| s.exp = None);
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "no expiration",
    );
    // exp before iat.
    let header = run(&|s| {
        s.iat = at + 10;
        s.exp = Some(at + 5);
    });
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "expires before it is issued",
    );
    // iat up to 30 s ahead is skew; 31 s is not.
    let header = run(&|s| {
        s.iat = at + 30;
        s.exp = Some(at + 330);
    });
    verify(&header, &network, &target, &body, at).await.unwrap();
    let header = run(&|s| {
        s.iat = at + 31;
        s.exp = Some(at + 331);
    });
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "not yet valid",
    );
    // nbf up to 30 s ahead is skew; 31 s is not.
    let header = run(&|s| s.nbf = Some(at + 30));
    verify(&header, &network, &target, &body, at).await.unwrap();
    let header = run(&|s| s.nbf = Some(at + 31));
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "not yet valid",
    );
}

#[tokio::test]
async fn cacao_nonce_must_be_present_and_bounded() {
    let owner = Wallet::new(1);
    let network = pkh_network(&owner);
    let target = prefix_target(&network, "foo");
    let at = now();
    for nonce in [String::new(), "n".repeat(257)] {
        let mut spec = CacaoSpec::valid(&owner, &target, at);
        spec.nonce = nonce;
        assert_refused(
            verify(
                &spec.header(&target),
                &network,
                &target,
                &body_for(&target),
                at,
            )
            .await,
            "nonce",
        );
    }
}

// --------------------------------------------------------- UCAN: accepted

fn did_key_network() -> (JWK, String, String, NetworkId) {
    let (jwk, did, vm) = did_key();
    let network = NetworkId::new(did.clone(), "default".to_string()).unwrap();
    (jwk, did, vm, network)
}

#[tokio::test]
async fn ucan_owner_prefix_and_key_deletes_are_accepted() {
    let (jwk, did, vm, network) = did_key_network();
    let at = now();
    for target in [
        prefix_target(&network, "foo"),
        key_target(&network, "apps/foo/token"),
    ] {
        let body = body_for(&target);
        let header = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at).header();
        let verified = verify(&header, &network, &target, &body, at).await.unwrap();
        assert_eq!(verified.owner, did);
        assert_eq!(verified.nonce, "urn:uuid:nonce-0001");
        assert_eq!(verified.exp, at + 300);
    }
}

// --------------------------------------------------------- UCAN: refusals

#[tokio::test]
async fn ucan_must_be_signed_by_the_owner() {
    let (_, _, owner_vm, network) = did_key_network();
    let (other_jwk, _, other_vm) = did_key();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let at = now();

    // Another key signs as itself: valid signature, not the owner.
    let header = UcanSpec::valid(&other_jwk, &other_vm, &network, &target, &body, at).header();
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "invoker is not the network owner",
    );
    // Another key signs while claiming to be the owner: bad signature.
    let header = UcanSpec::valid(&other_jwk, &owner_vm, &network, &target, &body, at).header();
    assert_refused(
        verify(&header, &network, &target, &body, at).await,
        "signature is invalid",
    );
}

#[tokio::test]
async fn ucan_cites_no_proofs_and_one_capability() {
    let (jwk, _, vm, network) = did_key_network();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let at = now();

    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.proof = vec![proof_cid()];
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "cites no proofs",
    );

    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.caps.push((
        prefix_target(&network, "bar").urn(),
        KEY_DELETE_ACTION.to_string(),
    ));
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "exactly one capability",
    );

    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.caveat = true;
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "not key.delete on exactly the requested target",
    );
}

#[tokio::test]
async fn ucan_capability_names_exactly_the_requested_target() {
    let (jwk, _, vm, network) = did_key_network();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let at = now();
    let wrong_resources = [
        prefix_target(&network, "bar").urn(),
        key_target(&network, "apps/foo/x").urn(),
        target.urn().strip_suffix('/').unwrap().to_string(),
        network.to_string(),
    ];
    for urn in wrong_resources {
        let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
        spec.caps = vec![(urn, KEY_DELETE_ACTION.to_string())];
        assert_refused(
            verify(&spec.header(), &network, &target, &body, at).await,
            "not key.delete on exactly the requested target",
        );
    }
    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.caps = vec![(target.urn(), KEY_BLOCK_ACTION.to_string())];
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "not key.delete on exactly the requested target",
    );
}

#[tokio::test]
async fn ucan_audience_and_facts_are_bound_to_the_request() {
    let (jwk, _, vm, network) = did_key_network();
    let other_network =
        NetworkId::new(network.owner_did().to_string(), "other".to_string()).unwrap();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let at = now();

    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.audience = OTHER_NODE.to_string();
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "audience is not this node",
    );

    let fact = |patch: &dyn Fn(&mut Value)| {
        let mut fact = admin_facts(&network, &target, &body);
        patch(&mut fact);
        fact
    };
    let facts: Vec<(&str, Value)> = vec![
        ("targetNode", fact(&|f| f["targetNode"] = json!(OTHER_NODE))),
        (
            "networkId",
            fact(&|f| f["networkId"] = json!(other_network.to_string())),
        ),
        // The path without its trailing slash.
        ("keyPath", fact(&|f| f["keyPath"] = json!("apps/foo"))),
        ("keyPath", fact(&|f| f["keyPath"] = json!("apps/bar/"))),
        ("action", fact(&|f| f["action"] = json!(KEY_BLOCK_ACTION))),
    ];
    for (field, fact) in facts {
        let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
        spec.facts = vec![fact];
        assert_refused(
            verify(&spec.header(), &network, &target, &body, at).await,
            "facts do not match the request",
        );
        let _ = field;
    }

    // The body hash covers the body the request sent.
    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.facts = vec![fact(&|f| f["bodyHash"] = json!(canonical_hash(&json!({}))))];
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "bodyHash",
    );
    let other_body = json!({ "keyPath": "apps/foo/", "extra": true });
    assert_refused(
        verify(
            &UcanSpec::valid(&jwk, &vm, &network, &target, &body, at).header(),
            &network,
            &target,
            &other_body,
            at,
        )
        .await,
        "bodyHash",
    );

    // Missing and wrong-typed facts.
    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.facts = vec![];
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "facts are missing",
    );
    let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
    spec.facts = vec![fact(&|f| {
        f["type"] = json!("tinycloud.encryption.key-describe/v1")
    })];
    assert_refused(
        verify(&spec.header(), &network, &target, &body, at).await,
        "facts are missing",
    );
}

#[tokio::test]
async fn ucan_lifetime_runs_from_nbf() {
    let (jwk, _, vm, network) = did_key_network();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let at = now();
    let spec = |mutate: &dyn Fn(&mut UcanSpec)| {
        let mut spec = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at);
        mutate(&mut spec);
        spec.header()
    };

    // exp - nbf = 300 is the longest accepted lifetime.
    verify(&spec(&|_| {}), &network, &target, &body, at)
        .await
        .unwrap();
    assert_refused(
        verify(&spec(&|s| s.exp = at + 301), &network, &target, &body, at).await,
        "lifetime exceeds 300 seconds",
    );
    // A long-lived credential is refused for its whole life, also near its
    // end: signed 35760 s ago for 36000 s, verified 240 s before it expires.
    let long = spec(&|s| {
        s.nbf = Some(at - 35_760);
        s.exp = at + 240;
    });
    assert_refused(
        verify(&long, &network, &target, &body, at).await,
        "lifetime exceeds 300 seconds",
    );
    // Without nbf there is no start to measure from.
    assert_refused(
        verify(&spec(&|s| s.nbf = None), &network, &target, &body, at).await,
        "must carry nbf",
    );
    // now < exp.
    let ended = spec(&|s| {
        s.nbf = Some(at - 100);
        s.exp = at;
    });
    assert_refused(
        verify(&ended, &network, &target, &body, at).await,
        "expired",
    );
    verify(&ended, &network, &target, &body, at - 1)
        .await
        .unwrap();
    // exp must come after nbf.
    let inverted = spec(&|s| {
        s.nbf = Some(at + 10);
        s.exp = at + 5;
    });
    assert_refused(
        verify(&inverted, &network, &target, &body, at).await,
        "expires before it is valid",
    );
    let empty = spec(&|s| {
        s.nbf = Some(at);
        s.exp = at + 100;
    });
    verify(&empty, &network, &target, &body, at).await.unwrap();
    // nbf up to 30 s ahead is skew; 31 s is not.
    verify(
        &spec(&|s| {
            s.nbf = Some(at + 30);
            s.exp = at + 330;
        }),
        &network,
        &target,
        &body,
        at,
    )
    .await
    .unwrap();
    assert_refused(
        verify(
            &spec(&|s| {
                s.nbf = Some(at + 31);
                s.exp = at + 331;
            }),
            &network,
            &target,
            &body,
            at,
        )
        .await,
        "not yet valid",
    );
    assert_refused(
        verify(&spec(&|s| s.nonce = None), &network, &target, &body, at).await,
        "nonce",
    );
}

// --------------------------------------------- credential and owner method

#[tokio::test]
async fn credential_type_must_match_the_owner_method() {
    let wallet = Wallet::new(1);
    let pkh = pkh_network(&wallet);
    let (jwk, _, vm, key_network) = did_key_network();
    let at = now();

    // A did:pkh owner presents a UCAN signed by some did:key.
    let target = prefix_target(&pkh, "foo");
    let body = body_for(&target);
    let ucan = UcanSpec::valid(&jwk, &vm, &pkh, &target, &body, at).header();
    assert_refused(
        verify(&ucan, &pkh, &target, &body, at).await,
        "does not match the network owner's DID method",
    );

    // A did:key owner presents a CACAO.
    let target = prefix_target(&key_network, "foo");
    let body = body_for(&target);
    let cacao = CacaoSpec::valid(&wallet, &target, at).header(&target);
    assert_refused(
        verify(&cacao, &key_network, &target, &body, at).await,
        "does not match the network owner's DID method",
    );
}

#[tokio::test]
async fn unsupported_owner_method_and_garbage_are_refused() {
    let network = NetworkId::new("did:web:example.com".to_string(), "default".to_string()).unwrap();
    let target = prefix_target(&network, "foo");
    let at = now();
    let (jwk, _, vm) = did_key();
    let body = body_for(&target);
    let ucan = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at).header();
    assert_refused(
        verify(&ucan, &network, &target, &body, at).await,
        "DID method does not support key deletion",
    );
    assert_refused(
        verify("not a credential", &network, &target, &body, at).await,
        "not a UCAN or a SIWE CACAO",
    );
}

// ------------------------------------------------------- nonce consumption

async fn service() -> (EncryptionService, DatabaseConnection) {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    let backend = std::sync::Arc::new(super::LocalOneOfOneBackend::new(ColumnEncryption::new(
        [0xABu8; 32],
    )));
    (
        EncryptionService::new(db.clone(), NODE.to_string(), backend),
        db,
    )
}

#[tokio::test]
async fn an_owner_nonce_is_consumed_once_and_kept_past_exp() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let (service, db) = service().await;
    let at = now();
    let header = CacaoSpec::valid(&wallet, &target, at).header(&target);

    service
        .authorize_owner_delete(&header, &network, &target, &body)
        .await
        .unwrap();
    let rows = encryption_nonce::Entity::find().all(&db).await.unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].requester_did, wallet.did());
    assert_eq!(rows[0].nonce, "nonce-0001");
    let kept_until = OffsetDateTime::parse(
        &rows[0].expires_at,
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap()
    .unix_timestamp();
    assert_eq!(kept_until, at + 300 + NONCE_RETENTION_SECS);

    // The same credential a second time is refused, not replayed.
    let second = service
        .authorize_owner_delete(&header, &network, &target, &body)
        .await;
    assert_refused(second, "nonce was already used");
}

#[tokio::test]
async fn nonces_past_their_expiry_are_pruned_and_live_ones_kept() {
    use sea_orm::ActiveModelTrait;
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let (service, db) = service().await;
    let ago = |seconds: i64| {
        OffsetDateTime::from_unix_timestamp(now() - seconds)
            .unwrap()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap()
    };
    let (ten_seconds_ago, a_minute_ago) = (ago(10), ago(60));
    for (requester, nonce, expires_at) in [
        ("did:key:old", "n-old", "2020-01-01T00:00:00Z"),
        // Within the 30 s window after its expiry a nonce is still kept.
        ("did:key:recent", "n-recent", ten_seconds_ago.as_str()),
        ("did:key:minute", "n-minute", a_minute_ago.as_str()),
        ("did:key:live", "n-live", "2999-01-01T00:00:00Z"),
    ] {
        encryption_nonce::ActiveModel {
            requester_did: sea_orm::ActiveValue::Set(requester.to_string()),
            nonce: sea_orm::ActiveValue::Set(nonce.to_string()),
            expires_at: sea_orm::ActiveValue::Set(expires_at.to_string()),
        }
        .insert(&db)
        .await
        .unwrap();
    }
    let header = CacaoSpec::valid(&wallet, &target, now()).header(&target);
    service
        .authorize_owner_delete(&header, &network, &target, &body)
        .await
        .unwrap();
    let mut kept: Vec<String> = encryption_nonce::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.nonce)
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        vec![
            "n-live".to_string(),
            "n-recent".to_string(),
            "nonce-0001".to_string()
        ]
    );
}

#[tokio::test]
async fn a_refused_credential_does_not_burn_its_nonce() {
    let wallet = Wallet::new(1);
    let network = pkh_network(&wallet);
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let (service, db) = service().await;
    let at = now();
    let mut spec = CacaoSpec::valid(&wallet, &target, at);
    spec.uri = format!("{KEY_DELETE_URI_PREFIX}{OTHER_NODE}");
    assert_refused(
        service
            .authorize_owner_delete(&spec.header(&target), &network, &target, &body)
            .await,
        "uri",
    );
    assert!(encryption_nonce::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn ucan_nonce_is_consumed_once_per_owner() {
    let (jwk, did, vm, network) = did_key_network();
    let target = prefix_target(&network, "foo");
    let body = body_for(&target);
    let (service, db) = service().await;
    let at = now();
    let header = UcanSpec::valid(&jwk, &vm, &network, &target, &body, at).header();
    service
        .authorize_owner_delete(&header, &network, &target, &body)
        .await
        .unwrap();
    let rows = encryption_nonce::Entity::find().all(&db).await.unwrap();
    assert_eq!(rows[0].requester_did, did);
    assert_refused(
        service
            .authorize_owner_delete(&header, &network, &target, &body)
            .await,
        "nonce was already used",
    );
}
