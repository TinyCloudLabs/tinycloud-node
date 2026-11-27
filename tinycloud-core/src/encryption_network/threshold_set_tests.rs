//! Threshold authorization set (TC-2225): certificate and activation
//! acceptance, the key-state merge, revocations carried with their chains,
//! and the node-bound refusals on a threshold network.

use std::collections::BTreeMap;

use k256::ecdsa::SigningKey;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection, EntityTrait,
    PaginatorTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use serde_json::{json, Value};
use sha3::{Digest, Keccak256};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{Cid, HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{encode_eip55, Message, TimeStamp},
        siwe_cacao::{Eip191, Payload as CacaoPayload, Signature as CacaoSignature},
    },
    resolver::DID_METHODS,
    siwe_recap::Capability as Recap,
    ssi::{
        claims::{jws::sign_bytes, jwt::NumericDate},
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload as UcanPayload,
    },
    ucan_capabilities_object::{Ability, Capabilities},
};
use tinycloud_threshold::{
    activation_preimage, readiness_preimage, CertificateBody, MemberIndex, ReadinessReceipt,
    SignedCertificate, SignedStatement,
};

use super::*;
use crate::{
    encryption_network::{
        backend::LocalOneOfOneBackend,
        key_id::KeyLocation,
        protocol::DECRYPT_ACTION,
        service::{EncryptionService, EncryptionServiceError},
    },
    migrations::Migrator,
};

const CHAIN: &str = include_str!("../../../tinycloud-threshold/vectors/v1/chain.json");
const PEER: &str = "did:key:z6MkPeerMember";

// --------------------------------------------------------------- identities

/// An Ed25519 `did:key` that signs UCANs and raw bytes.
struct Ident {
    jwk: JWK,
    did: String,
    vm: String,
}

fn ident() -> Ident {
    let mut jwk = JWK::generate_ed25519().unwrap();
    jwk.algorithm = Some(Algorithm::EdDSA);
    let did = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let fragment = did.rsplit_once(':').unwrap().1;
    let vm = format!("{did}#{fragment}");
    Ident { jwk, did, vm }
}

impl Ident {
    fn sign(&self, message: &[u8]) -> Vec<u8> {
        sign_bytes(Algorithm::EdDSA, message, &self.jwk).unwrap()
    }
}

/// A `did:pkh:eip155` wallet.
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

    fn sign_prehash(&self, digest: &[u8]) -> [u8; 65] {
        let (signature, recovery) = self.key.sign_prehash_recoverable(digest).unwrap();
        let mut bytes = [0u8; 65];
        bytes[..64].copy_from_slice(signature.to_bytes().as_ref());
        bytes[64] = u8::from(recovery) + 27;
        bytes
    }

    /// EIP-191 `personal_sign` of raw bytes.
    fn personal_sign(&self, message: &[u8]) -> Vec<u8> {
        let mut preimage = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
        preimage.extend_from_slice(message);
        self.sign_prehash(&Keccak256::digest(preimage)).to_vec()
    }
}

// Test fixture; a few of these live at once.
#[allow(clippy::large_enum_variant)]
enum Owner {
    Key(Ident),
    Pkh(Wallet),
}

impl Owner {
    fn did(&self) -> String {
        match self {
            Owner::Key(ident) => ident.did.clone(),
            Owner::Pkh(wallet) => wallet.did(),
        }
    }

    fn sign_raw(&self, message: &[u8]) -> Vec<u8> {
        match self {
            Owner::Key(ident) => ident.sign(message),
            Owner::Pkh(wallet) => wallet.personal_sign(message),
        }
    }
}

// --------------------------------------------------------------- fixtures

async fn fresh_db() -> DatabaseConnection {
    let mut options = ConnectOptions::new("sqlite::memory:".to_string());
    options.max_connections(1).sqlx_logging(false);
    let db = Database::connect(options).await.unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

fn node_keypair() -> Keypair {
    crate::keys::StaticSecret::new(vec![0x33; 32])
        .unwrap()
        .node_keypair()
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The genesis 2-of-3 certificate body of the shared vectors, with its
/// network, owner and member DIDs replaced.
fn certificate_body(network: &NetworkId, members: &[&str; 3]) -> CertificateBody {
    let vectors: Value = serde_json::from_str(CHAIN).unwrap();
    let v = hex::decode(
        vectors["cases"][0]["inputs"]["certificate"]["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let skip_lp =
        |at: usize| at + 4 + u32::from_be_bytes(v[at..at + 4].try_into().unwrap()) as usize;
    let mut at = skip_lp(skip_lp(1));
    // rekey, epoch, genesis t, t, n
    let fixed = &v[at..at + 22];
    at += 22;
    let count = u16::from_be_bytes(v[at..at + 2].try_into().unwrap());
    assert_eq!(count, 3);
    at += 2;
    for _ in 0..count {
        at = skip_lp(at + 2);
    }
    let mut out = vec![1];
    put(&mut out, network.to_string().as_bytes());
    put(&mut out, network.owner_did().as_bytes());
    out.extend_from_slice(fixed);
    out.extend_from_slice(&count.to_be_bytes());
    for (index, member) in (1u16..).zip(members) {
        out.extend_from_slice(&index.to_be_bytes());
        put(&mut out, member.as_bytes());
    }
    out.extend_from_slice(&v[at..]);
    CertificateBody::decode(&out).unwrap()
}

/// One node's view of a 2-of-3 threshold network: this node is member 1.
struct Fixture {
    db: DatabaseConnection,
    set: ThresholdSet,
    node: Keypair,
    owner: Owner,
    others: [Ident; 2],
    network: NetworkId,
    body: CertificateBody,
}

impl Fixture {
    async fn new(owner: Owner) -> Self {
        let db = fresh_db().await;
        let node = node_keypair();
        let set = ThresholdSet::new(db.clone(), node.clone(), None);
        let network = NetworkId::new(owner.did(), "vault".to_string()).unwrap();
        let others = [ident(), ident()];
        let body = certificate_body(&network, &[set.node_did(), &others[0].did, &others[1].did]);
        Self {
            db,
            set,
            node,
            owner,
            others,
            network,
            body,
        }
    }

    async fn did_key() -> Self {
        Self::new(Owner::Key(ident())).await
    }

    fn cert(&self) -> Vec<u8> {
        encode_cert(&SignedCertificate {
            body: self.body.clone(),
            owner_signature: self.owner.sign_raw(&self.body.owner_statement()),
        })
    }

    fn activation(&self) -> Vec<u8> {
        let receipts: Vec<ReadinessReceipt> = (1u16..=3)
            .map(|i| {
                let index = MemberIndex::new(i).unwrap();
                let preimage = readiness_preimage(&self.body, index).unwrap();
                let signature = match i {
                    1 => self.node.sign(&preimage).unwrap(),
                    _ => self.others[usize::from(i) - 2].sign(&preimage),
                };
                ReadinessReceipt { index, signature }
            })
            .collect();
        let bytes = activation_preimage(&self.body, &receipts).unwrap();
        let signature = self.owner.sign_raw(&bytes);
        encode_activation(&ActivationObject {
            certificate: self.body.digest().as_bytes()[..].try_into().unwrap(),
            receipts,
            activation: SignedStatement { bytes, signature },
        })
    }

    async fn accept(&self, kind: ObjectKind, bytes: &[u8]) -> Result<Accepted, AcceptError> {
        self.set
            .accept(&self.network, kind, bytes, Source::Client)
            .await
    }

    /// The set with this node's certificate activated.
    async fn activated(owner: Owner) -> Self {
        let fixture = Self::new(owner).await;
        fixture
            .accept(ObjectKind::Cert, &fixture.cert())
            .await
            .unwrap();
        fixture
            .accept(ObjectKind::Activation, &fixture.activation())
            .await
            .unwrap();
        fixture
    }

    fn key_urn(&self, path: &str) -> String {
        format!("{}/{path}", self.network)
    }

    fn key_state(&self, path: &str, action: &str, seq: u64, state: &str, version: u64) -> Vec<u8> {
        let caveat = json!({
            "version": 1,
            "network": self.network.to_string(),
            "owner": self.network.owner_did(),
            "action": action,
            "stateSeq": seq,
            "state": state,
            "keyVersion": version,
        });
        self.statement(&self.key_urn(path), KEY_STATE_ACTION, caveat, None)
    }

    fn network_revoke(&self) -> Vec<u8> {
        let caveat = json!({
            "version": 1,
            "network": self.network.to_string(),
            "owner": self.network.owner_did(),
        });
        self.statement(
            &self.network.to_string(),
            NETWORK_REVOKE_ACTION,
            caveat,
            None,
        )
    }

    /// An owner statement in the encoding its DID method takes. `expiry` is
    /// set on a SIWE message only.
    fn statement(
        &self,
        resource: &str,
        ability: &str,
        caveat: Value,
        expiry: Option<i64>,
    ) -> Vec<u8> {
        let nb: BTreeMap<String, Value> = serde_json::from_value(caveat).unwrap();
        match &self.owner {
            Owner::Key(owner) => {
                let mut caps = Capabilities::new();
                caps.with_action(
                    resource.parse().unwrap(),
                    ability.parse::<Ability>().unwrap(),
                    [nb],
                );
                UcanPayload {
                    issuer: owner.vm.parse::<DIDURLBuf>().unwrap(),
                    audience: owner.did.parse::<DIDBuf>().unwrap(),
                    not_before: None,
                    // Long past: a statement's `exp` is not read.
                    expiration: NumericDate::try_from_seconds(1.0).unwrap(),
                    nonce: Some("statement".to_string()),
                    facts: Some(Vec::<Value>::new()),
                    proof: vec![],
                    attenuation: caps,
                }
                .sign(Algorithm::EdDSA, &owner.jwk)
                .unwrap()
                .encode()
                .unwrap()
                .into_bytes()
            }
            Owner::Pkh(wallet) => {
                let mut recap = Recap::<Value>::default();
                recap
                    .with_action_convert(resource, ability, vec![nb])
                    .unwrap();
                let message = recap
                    .build_message(Message {
                        scheme: None,
                        domain: "example.com".parse().unwrap(),
                        address: wallet.address,
                        statement: None,
                        uri: self.network.to_string().parse().unwrap(),
                        version: tinycloud_auth::cacaos::siwe::Version::V1,
                        chain_id: 1,
                        nonce: "statement01".to_string(),
                        issued_at: TimeStamp::from(
                            OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap(),
                        ),
                        expiration_time: expiry.map(|t| {
                            TimeStamp::from(OffsetDateTime::from_unix_timestamp(t).unwrap())
                        }),
                        not_before: None,
                        request_id: None,
                        resources: vec![],
                    })
                    .unwrap();
                let signature =
                    CacaoSignature::from(wallet.sign_prehash(&message.eip191_hash().unwrap()));
                let cacao = CacaoPayload::from(message).sign::<Eip191>(signature);
                TinyCloudDelegation::Cacao(Box::new(cacao))
                    .encode()
                    .unwrap()
                    .into_bytes()
            }
        }
    }

    async fn row(&self, path: &str) -> threshold_key_row::Model {
        threshold_key_row::Entity::find_by_id((self.network.to_string(), path.to_string()))
            .one(&self.db)
            .await
            .unwrap()
            .unwrap()
    }

    async fn faults(&self) -> u64 {
        threshold_fault::Entity::find()
            .count(&self.db)
            .await
            .unwrap()
    }
}

fn refusal(result: Result<Accepted, AcceptError>) -> &'static str {
    match result {
        Err(AcceptError::Refused(reason)) => reason,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

fn unavailable(result: Result<Accepted, AcceptError>) -> &'static str {
    match result {
        Err(AcceptError::Unavailable(reason)) => reason,
        other => panic!("expected unavailable, got {other:?}"),
    }
}

// ---------------------------------------------------------- cert/activation

#[tokio::test]
async fn certificate_then_activation_are_held_and_only_they_are_served() {
    let f = Fixture::did_key().await;
    assert_eq!(
        unavailable(f.accept(ObjectKind::Activation, &f.activation()).await),
        "certificate_missing"
    );
    let cert = f.accept(ObjectKind::Cert, &f.cert()).await.unwrap();
    assert!(cert.new);
    assert!(!f.accept(ObjectKind::Cert, &f.cert()).await.unwrap().new);
    let activation = f
        .accept(ObjectKind::Activation, &f.activation())
        .await
        .unwrap();
    assert!(activation.new);
    f.accept(
        ObjectKind::KeyState,
        &f.key_state("docs/a", "create", 1, "active", 1),
    )
    .await
    .unwrap();

    let chain = f.set.chain(&f.network).await.unwrap();
    let kinds: Vec<&str> = chain.iter().map(|(kind, _, _)| kind.as_str()).collect();
    assert_eq!(kinds.len(), 2);
    assert!(kinds.contains(&"cert") && kinds.contains(&"activation"));
    assert!(chain
        .iter()
        .all(|(_, cid, bytes)| *cid == object_cid(bytes)));
}

#[tokio::test]
async fn a_certificate_for_another_network_or_signer_is_refused() {
    let f = Fixture::did_key().await;
    let other = NetworkId::new(f.network.owner_did().to_string(), "other".to_string()).unwrap();
    assert_eq!(
        refusal(
            f.set
                .accept(&other, ObjectKind::Cert, &f.cert(), Source::Client)
                .await
        ),
        "certificate_invalid"
    );
    let forged = encode_cert(&SignedCertificate {
        body: f.body.clone(),
        owner_signature: f.others[0].sign(&f.body.owner_statement()),
    });
    assert_eq!(
        refusal(f.accept(ObjectKind::Cert, &forged).await),
        "certificate_invalid"
    );
}

#[tokio::test]
async fn a_refused_peer_object_is_a_fault_and_a_client_one_is_not() {
    let f = Fixture::did_key().await;
    let garbage = b"not a certificate".to_vec();
    refusal(f.accept(ObjectKind::Cert, &garbage).await);
    assert_eq!(f.faults().await, 0);
    refusal(
        f.set
            .accept(&f.network, ObjectKind::Cert, &garbage, Source::Peer(PEER))
            .await,
    );
    let fault = threshold_fault::Entity::find()
        .one(&f.db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(fault.source_did, PEER);
    assert_eq!(fault.object_cid, object_cid(&garbage));
    // A missing prerequisite is no fault.
    unavailable(
        f.set
            .accept(
                &f.network,
                ObjectKind::Activation,
                &f.activation(),
                Source::Peer(PEER),
            )
            .await,
    );
    assert_eq!(f.faults().await, 1);
}

// ----------------------------------------------------------------- merge

#[tokio::test]
async fn key_state_needs_an_activated_certificate_naming_this_node() {
    let f = Fixture::did_key().await;
    f.accept(ObjectKind::Cert, &f.cert()).await.unwrap();
    assert_eq!(
        unavailable(
            f.accept(
                ObjectKind::KeyState,
                &f.key_state("docs/a", "create", 1, "active", 1)
            )
            .await
        ),
        "not_a_member"
    );
}

#[tokio::test]
async fn the_highest_state_seq_wins_in_any_order() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    let path = "docs/a";
    let create = f.key_state(path, "create", 1, "active", 1);
    let block = f.key_state(path, "block", 3, "blocked", 1);
    let stale = f.key_state(path, "unblock", 2, "active", 1);

    let first = f.accept(ObjectKind::KeyState, &create).await.unwrap();
    assert_eq!(
        first.key,
        Some(KeyView {
            path: path.to_string(),
            state_seq: 1,
            state: "active".to_string(),
            key_version: 1,
        })
    );
    f.accept(ObjectKind::KeyState, &block).await.unwrap();
    let after = f.accept(ObjectKind::KeyState, &stale).await.unwrap();
    // The lower stateSeq is held but changes nothing.
    assert!(after.new);
    assert_eq!(
        after.key.as_ref().map(|k| (k.state_seq, k.state.as_str())),
        Some((3, "blocked"))
    );
    // A replay is a no-op answered with the current state.
    let replay = f.accept(ObjectKind::KeyState, &create).await.unwrap();
    assert!(!replay.new);
    assert_eq!(replay.key.unwrap().state_seq, 3);
    let row = f.row(path).await;
    assert_eq!(
        (row.state_seq, row.state.as_str(), row.conflict),
        (3, "blocked", false)
    );
    assert_eq!(row.statement_cid, object_cid(&block));
}

#[tokio::test]
async fn conflicting_statements_at_one_state_seq_block_the_key_identically_in_any_order() {
    let owner = ident();
    let jwk = owner.jwk.clone();
    let mut rows = Vec::new();
    for reversed in [false, true] {
        let owner = Ident {
            jwk: jwk.clone(),
            did: owner.did.clone(),
            vm: owner.vm.clone(),
        };
        let f = Fixture::activated(Owner::Key(owner)).await;
        let a = f.key_state("docs/a", "unblock", 5, "active", 2);
        let b = f.key_state("docs/a", "block", 5, "blocked", 3);
        let order = if reversed { [&b, &a] } else { [&a, &b] };
        f.accept(ObjectKind::KeyState, order[0]).await.unwrap();
        let second = f.accept(ObjectKind::KeyState, order[1]).await.unwrap();
        assert_eq!(second.key.unwrap().state, "blocked");
        let row = f.row("docs/a").await;
        assert!(row.conflict);
        assert_eq!(row.key_version, 3);
        assert_eq!(row.statement_cid, object_cid(&a).min(object_cid(&b)));
        let fault = threshold_fault::Entity::find()
            .one(&f.db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(fault.source_did, f.network.owner_did());
        assert_eq!(fault.reason, "key_state_conflict");

        // A higher stateSeq clears the conflict.
        f.accept(
            ObjectKind::KeyState,
            &f.key_state("docs/a", "unblock", 6, "active", 3),
        )
        .await
        .unwrap();
        let cleared = f.row("docs/a").await;
        assert_eq!(
            (cleared.state.as_str(), cleared.conflict),
            ("active", false)
        );
        rows.push((row.state, row.key_version, row.statement_cid, row.conflict));
    }
    assert_eq!(rows[0], rows[1]);
}

#[tokio::test]
async fn network_revoke_reports_every_key_revoked() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    f.accept(
        ObjectKind::KeyState,
        &f.key_state("docs/a", "create", 1, "active", 1),
    )
    .await
    .unwrap();
    let revoke = f
        .accept(ObjectKind::KeyState, &f.network_revoke())
        .await
        .unwrap();
    assert_eq!(revoke.key, None);
    let later = f
        .accept(
            ObjectKind::KeyState,
            &f.key_state("docs/a", "unblock", 9, "active", 1),
        )
        .await
        .unwrap();
    assert_eq!(later.key.unwrap().state, "revoked");
    // network.revoke is never served.
    assert_eq!(f.set.chain(&f.network).await.unwrap().len(), 2);
}

#[tokio::test]
async fn deletable_paths_and_out_of_range_sequences_are_refused() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    for path in ["apps/one/key", "secrets/x"] {
        assert_eq!(
            refusal(
                f.accept(
                    ObjectKind::KeyState,
                    &f.key_state(path, "create", 1, "active", 1)
                )
                .await
            ),
            "deletable_key_path"
        );
    }
    f.accept(
        ObjectKind::KeyState,
        &f.key_state("docs/x", "create", 1, "active", 1),
    )
    .await
    .unwrap();
    assert_eq!(
        refusal(
            f.accept(
                ObjectKind::KeyState,
                &f.key_state("docs/x", "block", MAX_STATE_SEQ + 1, "blocked", 1)
            )
            .await
        ),
        "statement_sequence_range"
    );
    let top = f
        .accept(
            ObjectKind::KeyState,
            &f.key_state("docs/x", "block", MAX_STATE_SEQ, "blocked", 1),
        )
        .await
        .unwrap();
    assert_eq!(top.key.unwrap().state_seq, MAX_STATE_SEQ);
}

#[tokio::test]
async fn a_statement_from_anyone_but_the_owner_or_with_a_wrong_label_is_refused() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    // Same network, another signer.
    let forged = Fixture {
        owner: Owner::Key(ident()),
        network: f.network.clone(),
        ..Fixture::did_key().await
    };
    assert_eq!(
        refusal(
            f.accept(
                ObjectKind::KeyState,
                &forged.key_state("docs/a", "create", 1, "active", 1)
            )
            .await
        ),
        "statement_signer"
    );
    assert_eq!(
        refusal(
            f.accept(
                ObjectKind::KeyState,
                &f.key_state("docs/a", "block", 2, "active", 1)
            )
            .await
        ),
        "statement_action_state"
    );
}

#[tokio::test]
async fn a_wallet_owner_signs_certificates_and_siwe_statements() {
    let f = Fixture::activated(Owner::Pkh(Wallet::new(7))).await;
    let accepted = f
        .accept(
            ObjectKind::KeyState,
            &f.key_state("docs/a", "create", 1, "active", 1),
        )
        .await
        .unwrap();
    assert_eq!(accepted.key.unwrap().state, "active");
    let caveat = json!({
        "version": 1,
        "network": f.network.to_string(),
        "owner": f.network.owner_did(),
        "action": "block",
        "stateSeq": 2,
        "state": "blocked",
        "keyVersion": 1,
    });
    let expiring = f.statement(
        &f.key_urn("docs/a"),
        KEY_STATE_ACTION,
        caveat,
        Some(now() + 60),
    );
    assert_eq!(
        refusal(f.accept(ObjectKind::KeyState, &expiring).await),
        "statement_binding"
    );
}

#[tokio::test]
async fn the_ack_is_signed_by_the_node_over_the_documented_preimage() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    let accepted = f
        .accept(
            ObjectKind::KeyState,
            &f.key_state("docs/a", "create", 1, "active", 1),
        )
        .await
        .unwrap();
    let ack = f.set.ack(&f.network, "client-nonce-1", &accepted).unwrap();
    let preimage = ack_preimage(
        &f.network.to_string(),
        "client-nonce-1",
        &accepted.cid,
        "accepted",
        accepted.key.as_ref(),
    );
    let signature = URL_SAFE_NO_PAD.decode(&ack.signature).unwrap();
    assert!(f.node.public().verify(&preimage, &signature));
    assert_eq!(ack.node, f.set.node_did());
    assert!(f.set.ack(&f.network, "", &accepted).is_err());
}

// ------------------------------------------------------------ revocation

fn cid_of(header: &str) -> Cid {
    hash(header.as_bytes()).to_cid(RAW_CODEC)
}

fn ucan(
    issuer: &Ident,
    audience: &str,
    caps: &[(&str, &str)],
    proof: Vec<Cid>,
    nbf: Option<i64>,
    exp: i64,
) -> String {
    let mut capabilities = Capabilities::new();
    for (resource, ability) in caps {
        capabilities.with_action(
            resource.parse().unwrap(),
            ability.parse::<Ability>().unwrap(),
            [BTreeMap::<String, Value>::new()],
        );
    }
    UcanPayload {
        issuer: issuer.vm.parse::<DIDURLBuf>().unwrap(),
        audience: audience.parse::<DIDBuf>().unwrap(),
        not_before: nbf.map(|t| NumericDate::try_from_seconds(t as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(exp as f64).unwrap(),
        nonce: Some(format!("n-{}", now())),
        facts: Some(Vec::<Value>::new()),
        proof,
        attenuation: capabilities,
    }
    .sign(Algorithm::EdDSA, &issuer.jwk)
    .unwrap()
    .encode()
    .unwrap()
}

fn revocation_object(revocation: &str, delegations: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&RevocationObject {
        revocation: revocation.to_string(),
        delegations: delegations.iter().map(|d| d.to_string()).collect(),
    })
    .unwrap()
}

/// Owner → A → B on one key of the network, both long expired.
struct Chain {
    a: Ident,
    b: Ident,
    root: String,
    leaf: String,
}

fn chain(f: &Fixture, owner: &Ident) -> Chain {
    let (a, b) = (ident(), ident());
    let urn = f.key_urn("docs/a");
    let root = ucan(
        owner,
        &a.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![],
        None,
        1_000,
    );
    let leaf = ucan(
        &a,
        &b.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&root)],
        None,
        1_000,
    );
    Chain { a, b, root, leaf }
}

fn revoke(issuer: &Ident, target: &str, proof: Vec<Cid>, nbf: i64, exp: i64) -> String {
    ucan(
        issuer,
        &issuer.did,
        &[(&format!("urn:cid:{}", cid_of(target)), REVOKE_ABILITY)],
        proof,
        Some(nbf),
        exp,
    )
}

async fn revocations(db: &DatabaseConnection, target: &str) -> u64 {
    revocation::Entity::find()
        .filter(revocation::Column::Revoked.eq(hash(target.as_bytes())))
        .count(db)
        .await
        .unwrap()
}

async fn did_key_owner() -> (Fixture, Ident) {
    let owner = ident();
    let copy = Ident {
        jwk: owner.jwk.clone(),
        did: owner.did.clone(),
        vm: owner.vm.clone(),
    };
    (Fixture::activated(Owner::Key(copy)).await, owner)
}

#[tokio::test]
async fn the_delegator_revokes_with_its_expired_chain_attached() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let t = now();
    let object = revocation_object(
        &revoke(&c.a, &c.leaf, vec![], t, t + 300),
        &[&c.leaf, &c.root],
    );
    assert!(f.accept(ObjectKind::Revocation, &object).await.unwrap().new);
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
    assert_eq!(delegation::Entity::find().count(&f.db).await.unwrap(), 2);
    // Held once; a replay changes nothing.
    assert!(!f.accept(ObjectKind::Revocation, &object).await.unwrap().new);
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[tokio::test]
async fn the_owner_revokes_and_the_delegatee_alone_may_not() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let t = now();
    let by_delegatee = revocation_object(
        &revoke(&c.b, &c.leaf, vec![], t, t + 300),
        &[&c.leaf, &c.root],
    );
    assert_eq!(
        refusal(f.accept(ObjectKind::Revocation, &by_delegatee).await),
        "revoker_unauthorized"
    );
    let by_owner = revocation_object(
        &revoke(&owner, &c.leaf, vec![], t, t + 300),
        &[&c.leaf, &c.root],
    );
    f.accept(ObjectKind::Revocation, &by_owner).await.unwrap();
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[tokio::test]
async fn a_chain_must_be_complete_and_in_the_network() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let t = now();
    let missing = revocation_object(&revoke(&c.a, &c.leaf, vec![], t, t + 300), &[&c.leaf]);
    assert_eq!(
        refusal(f.accept(ObjectKind::Revocation, &missing).await),
        "chain_incomplete"
    );
    // A delegation on another network of the same owner is out of scope.
    let elsewhere = format!(
        "{}/docs/a",
        NetworkId::new(owner.did.clone(), "other".to_string()).unwrap()
    );
    let foreign = ucan(
        &owner,
        &c.a.did,
        &[(&elsewhere, DECRYPT_ACTION)],
        vec![],
        None,
        1_000,
    );
    let object = revocation_object(&revoke(&owner, &foreign, vec![], t, t + 300), &[&foreign]);
    assert_eq!(
        refusal(f.accept(ObjectKind::Revocation, &object).await),
        "out_of_scope"
    );
    assert_eq!(revocations(&f.db, &c.leaf).await, 0);
}

#[tokio::test]
async fn a_control_grant_counts_only_inside_the_authority_window() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let holder = ident();
    let t = now();
    let target = format!("urn:cid:{}", cid_of(&c.leaf));
    let expired_grant = ucan(
        &c.a,
        &holder.did,
        &[(&target, REVOKE_ABILITY)],
        vec![],
        None,
        t - 4_000,
    );
    let object = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&expired_grant)], t, t + 300),
        &[&c.leaf, &c.root, &expired_grant],
    );
    assert_eq!(
        refusal(f.accept(ObjectKind::Revocation, &object).await),
        "control_grant_window"
    );
    let grant = ucan(
        &c.a,
        &holder.did,
        &[(&target, REVOKE_ABILITY)],
        vec![],
        None,
        t + 600,
    );
    let object = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&grant)], t, t + 300),
        &[&c.leaf, &c.root, &grant],
    );
    f.accept(ObjectKind::Revocation, &object).await.unwrap();
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[test]
fn the_authority_window_follows_what_the_revocation_carries() {
    assert_eq!(
        authority_window(Some(10), Some(5), Some(100)),
        Some((10, 100))
    );
    assert_eq!(authority_window(None, Some(5), None), Some((5, 3_605)));
    assert_eq!(
        authority_window(None, None, Some(5_000)),
        Some((1_400, 5_000))
    );
    assert_eq!(authority_window(None, None, None), None);
    let at = |t: i64| Some(OffsetDateTime::from_unix_timestamp(t).unwrap());
    assert!(intersects((10, 100), None, at(11)));
    assert!(!intersects((10, 100), None, at(10)));
    assert!(intersects((10, 100), at(100), None));
    assert!(!intersects((10, 100), at(101), None));
}

// ----------------------------------------------- node-bound and key.create

async fn threshold_row(db: &DatabaseConnection, network: &NetworkId, backend: &str, t: i32) {
    encryption_network::Entity::insert(encryption_network::ActiveModel {
        network_id: Set(network.to_string()),
        owner_did: Set(network.owner_did().to_string()),
        name: Set(network.name().to_string()),
        alg: Set("threshold".to_string()),
        key_version: Set(1),
        public_key: Set(vec![]),
        state: Set("active".to_string()),
        threshold_n: Set(3),
        threshold_t: Set(t),
        key_backend: Set(backend.to_string()),
        sealed_private_key: Set(None),
        created_at: Set("2026-01-01T00:00:00Z".to_string()),
        updated_at: Set("2026-01-01T00:00:00Z".to_string()),
    })
    .exec(db)
    .await
    .unwrap();
    crate::models::encryption_network_member::Entity::insert(
        crate::models::encryption_network_member::ActiveModel {
            network_id: Set(network.to_string()),
            node_id: Set("did:key:z6MkNodeTest".to_string()),
            role: Set("member".to_string()),
            share_index: Set(1),
            joined_at: Set("2026-01-01T00:00:00Z".to_string()),
        },
    )
    .exec(db)
    .await
    .unwrap();
}

fn service(db: &DatabaseConnection) -> EncryptionService {
    let backend = std::sync::Arc::new(LocalOneOfOneBackend::new(ColumnEncryption::new([0xAB; 32])));
    EncryptionService::new(db.clone(), "did:key:z6MkNodeTest".to_string(), backend)
}

fn invocation(network: &NetworkId) -> crate::util::InvocationInfo {
    let session = ident();
    let ucan = UcanPayload {
        issuer: session.vm.parse::<DIDURLBuf>().unwrap(),
        audience: "did:key:z6MkNodeTest".parse::<DIDBuf>().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds((now() + 60) as f64).unwrap(),
        nonce: Some("admin".to_string()),
        facts: Some(Vec::<Value>::new()),
        proof: vec![cid_of("parent")],
        attenuation: {
            let mut caps = Capabilities::new();
            caps.with_action(
                network.to_string().parse().unwrap(),
                "tinycloud.encryption/network.revoke"
                    .parse::<Ability>()
                    .unwrap(),
                [BTreeMap::<String, Value>::new()],
            );
            caps
        },
    }
    .sign(Algorithm::EdDSA, &session.jwk)
    .unwrap();
    crate::util::InvocationInfo::try_from(ucan).unwrap()
}

#[tokio::test]
async fn a_threshold_network_refuses_node_bound_credentials() {
    let db = fresh_db().await;
    let threshold = NetworkId::new(ident().did, "vault".to_string()).unwrap();
    let local = NetworkId::new(ident().did, "vault".to_string()).unwrap();
    threshold_row(&db, &threshold, "threshold", 2).await;
    threshold_row(&db, &local, "local", 1).await;
    let service = service(&db);
    let body = json!({});
    let key = KeyLocation::new(&threshold, "docs/a").unwrap();
    let network_admin = service
        .verify_network_admin_authorized(&threshold, "x", &invocation(&threshold), &body)
        .await;
    assert!(matches!(
        network_admin,
        Err(EncryptionServiceError::OwnerOnly(_))
    ));
    let key_admin = service
        .verify_key_admin_authorized(&threshold, &key, "x", &invocation(&threshold), &body)
        .await;
    assert!(matches!(
        key_admin,
        Err(EncryptionServiceError::OwnerOnly(_))
    ));
    let unchanged = service
        .verify_network_admin_authorized(&local, "x", &invocation(&local), &body)
        .await;
    assert!(!matches!(
        unchanged,
        Err(EncryptionServiceError::OwnerOnly(_))
    ));
}

#[tokio::test]
async fn key_create_refuses_deletable_paths_on_a_threshold_network() {
    let db = fresh_db().await;
    let network = NetworkId::new(ident().did, "vault".to_string()).unwrap();
    threshold_row(&db, &network, "threshold", 2).await;
    let service = service(&db);
    for path in ["apps/one/key", "secrets/x"] {
        let loc = KeyLocation::new(&network, path).unwrap();
        match service.create_key(&loc, true).await {
            Err(EncryptionServiceError::KeyPathInvalid(reason)) => {
                assert!(reason.contains("threshold"), "{reason}")
            }
            other => panic!("expected key_path_invalid, got {other:?}"),
        }
    }
}
