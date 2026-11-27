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
    siwe_recap::Capability as Recap,
    ssi::{
        claims::{jws::sign_bytes, jwt::NumericDate},
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, Params, JWK},
        ucan::Payload as UcanPayload,
    },
    ucan_capabilities_object::{Ability, Capabilities},
};
use tinycloud_threshold::{
    activation_preimage, readiness_preimage, CertificateBody, ReadinessReceipt, SignedCertificate,
    SignedStatement,
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
    let Params::OKP(okp) = &jwk.params else {
        unreachable!("an Ed25519 key")
    };
    let multicodec = [[0xed, 0x01].as_slice(), okp.public_key.0.as_slice()].concat();
    let did = format!(
        "did:key:{}",
        tinycloud_auth::ipld_core::cid::multibase::encode(
            tinycloud_auth::ipld_core::cid::multibase::Base::Base58Btc,
            multicodec
        )
    );
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

/// The certificate body of vector chain case `case` (0: genesis 2-of-3,
/// 1: its reshare 3-of-4), with its network, owner and member DIDs replaced
/// and, for a successor, `previous` as its predecessor.
fn spliced_body(
    case: usize,
    network: &NetworkId,
    members: &[&str],
    previous: Option<&CertificateBody>,
) -> CertificateBody {
    let vectors: Value = serde_json::from_str(CHAIN).unwrap();
    let v = hex::decode(
        vectors["cases"][case]["inputs"]["certificate"]["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let u16_at = |at: usize| u16::from_be_bytes(v[at..at + 2].try_into().unwrap());
    let skip_lp =
        |at: usize| at + 4 + u32::from_be_bytes(v[at..at + 4].try_into().unwrap()) as usize;
    let mut at = skip_lp(skip_lp(1));
    // rekey, epoch, genesis t, t, n
    let fixed = &v[at..at + 22];
    at += 22;
    let count = u16_at(at);
    assert_eq!(usize::from(count), members.len());
    at += 2;
    let mut indices = Vec::new();
    for _ in 0..count {
        indices.push(u16_at(at));
        at = skip_lp(at + 2);
    }
    let mut out = vec![1];
    put(&mut out, network.to_string().as_bytes());
    put(&mut out, network.owner_did().as_bytes());
    out.extend_from_slice(fixed);
    out.extend_from_slice(&count.to_be_bytes());
    for (index, member) in indices.into_iter().zip(members) {
        out.extend_from_slice(&index.to_be_bytes());
        put(&mut out, member.as_bytes());
    }
    // Master public key, commitments, transcript; then the predecessor.
    let end = at + 96 + 2 + 96 * usize::from(u16_at(at + 96)) + 32;
    out.extend_from_slice(&v[at..end]);
    let mut rest = &v[end..];
    if let Some(previous) = previous {
        assert_eq!(rest[0], 1);
        out.push(1);
        out.extend_from_slice(previous.digest().as_bytes());
        rest = &rest[33..];
    }
    out.extend_from_slice(rest);
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
        let set =
            ThresholdSet::new(db.clone(), node.clone(), None).with_delegation_rules(false, true);
        let network = NetworkId::new(owner.did(), "vault".to_string()).unwrap();
        let others = [ident(), ident()];
        let body = spliced_body(
            0,
            &network,
            &[set.node_did(), &others[0].did, &others[1].did],
            None,
        );
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
        self.cert_of(&self.body)
    }

    fn cert_of(&self, body: &CertificateBody) -> Vec<u8> {
        encode_cert(&SignedCertificate {
            body: body.clone(),
            owner_signature: self.owner.sign_raw(&body.owner_statement()),
        })
    }

    fn activation(&self) -> Vec<u8> {
        self.activation_of(&self.body, &[])
    }

    /// The owner's activation of `body`, with a readiness receipt from each
    /// member: this node, `others` or `more`.
    fn activation_of(&self, body: &CertificateBody, more: &[&Ident]) -> Vec<u8> {
        self.activation_with(body, &[&self.node], more)
    }

    /// The owner's activation of `body`, with a readiness receipt from each
    /// member: a node of `nodes`, `others` or `more`.
    fn activation_with(
        &self,
        body: &CertificateBody,
        nodes: &[&Keypair],
        more: &[&Ident],
    ) -> Vec<u8> {
        let receipts: Vec<ReadinessReceipt> = body
            .members()
            .iter()
            .map(|member| {
                let preimage = readiness_preimage(body, member.index).unwrap();
                let node = nodes
                    .iter()
                    .find(|node| public_key_to_did_key(node.public()) == member.node.as_str());
                let signature = if let Some(node) = node {
                    node.sign(&preimage).unwrap()
                } else {
                    self.others
                        .iter()
                        .chain(more.iter().copied())
                        .find(|ident| ident.did == member.node.as_str())
                        .unwrap()
                        .sign(&preimage)
                };
                ReadinessReceipt {
                    index: member.index,
                    signature,
                }
            })
            .collect();
        let bytes = activation_preimage(body, &receipts).unwrap();
        let signature = self.owner.sign_raw(&bytes);
        encode_activation(&ActivationObject {
            certificate: body.digest().as_bytes()[..].try_into().unwrap(),
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
    ucan_with_caveat(
        issuer,
        audience,
        caps,
        BTreeMap::new(),
        vec![],
        proof,
        nbf,
        exp,
    )
}

/// As [`ucan`], every capability carrying `caveat`, with `facts`.
#[allow(clippy::too_many_arguments)]
fn ucan_with_caveat(
    issuer: &Ident,
    audience: &str,
    caps: &[(&str, &str)],
    caveat: BTreeMap<String, Value>,
    facts: Vec<Value>,
    proof: Vec<Cid>,
    nbf: Option<i64>,
    exp: i64,
) -> String {
    let mut capabilities = Capabilities::new();
    for (resource, ability) in caps {
        capabilities.with_action(
            resource.parse().unwrap(),
            ability.parse::<Ability>().unwrap(),
            [caveat.clone()],
        );
    }
    UcanPayload {
        issuer: issuer.vm.parse::<DIDURLBuf>().unwrap(),
        audience: audience.parse::<DIDBuf>().unwrap(),
        not_before: nbf.map(|t| NumericDate::try_from_seconds(t as f64).unwrap()),
        expiration: NumericDate::try_from_seconds(exp as f64).unwrap(),
        nonce: Some(format!("n-{}", now())),
        facts: Some(facts),
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
        &owner,
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
        &owner,
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

// ------------------------------------------- network rows and membership

/// N's network row and its member rows, as `index:node`.
async fn network_rows(
    db: &DatabaseConnection,
    network: &NetworkId,
) -> (Option<encryption_network::Model>, Vec<String>) {
    use crate::models::encryption_network_member;
    let row = encryption_network::Entity::find_by_id(network.to_string())
        .one(db)
        .await
        .unwrap();
    let mut members: Vec<String> = encryption_network_member::Entity::find()
        .filter(encryption_network_member::Column::NetworkId.eq(network.to_string()))
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|member| format!("{}:{}", member.share_index, member.node_id))
        .collect();
    members.sort();
    (row, members)
}

#[tokio::test]
async fn the_activated_genesis_creates_the_network_and_its_member_rows() {
    let f = Fixture::did_key().await;
    f.accept(ObjectKind::Cert, &f.cert()).await.unwrap();
    assert!(network_rows(&f.db, &f.network).await.0.is_none());
    f.accept(ObjectKind::Activation, &f.activation())
        .await
        .unwrap();
    let (row, members) = network_rows(&f.db, &f.network).await;
    let row = row.unwrap();
    assert_eq!(
        (
            row.key_backend.as_str(),
            row.state.as_str(),
            row.owner_did.as_str(),
            row.threshold_t,
            row.threshold_n,
            row.sealed_private_key.is_none(),
        ),
        ("threshold", "active", f.network.owner_did(), 2, 3, true)
    );
    assert_eq!(
        row.public_key,
        f.body
            .public_material()
            .master_public_key()
            .encode()
            .to_vec()
    );
    let mut expected: Vec<String> = f
        .body
        .members()
        .iter()
        .map(|member| format!("{}:{}", member.index.get(), member.node.as_str()))
        .collect();
    expected.sort();
    assert_eq!(members, expected);

    // Accepting the activation again (here after losing its object) keeps
    // the rows as they are.
    threshold_set_object::Entity::delete_many()
        .filter(threshold_set_object::Column::Kind.eq(ObjectKind::Activation.as_str()))
        .exec(&f.db)
        .await
        .unwrap();
    assert!(
        f.accept(ObjectKind::Activation, &f.activation())
            .await
            .unwrap()
            .new
    );
    assert_eq!(network_rows(&f.db, &f.network).await, (Some(row), members));

    // B3-1 holds for a network that exists only through this path.
    let service = service(&f.db);
    let body = json!({});
    let key = KeyLocation::new(&f.network, "docs/a").unwrap();
    assert!(matches!(
        service
            .verify_network_admin_authorized(&f.network, "x", &invocation(&f.network), &body)
            .await,
        Err(EncryptionServiceError::OwnerOnly(_))
    ));
    assert!(matches!(
        service
            .verify_key_admin_authorized(&f.network, &key, "x", &invocation(&f.network), &body)
            .await,
        Err(EncryptionServiceError::OwnerOnly(_))
    ));
}

#[tokio::test]
async fn a_genesis_for_a_network_this_node_serves_otherwise_is_unavailable() {
    let f = Fixture::did_key().await;
    threshold_row(&f.db, &f.network, "local", 1).await;
    f.accept(ObjectKind::Cert, &f.cert()).await.unwrap();
    assert_eq!(
        unavailable(f.accept(ObjectKind::Activation, &f.activation()).await),
        "network_exists"
    );
}

#[tokio::test]
async fn a_member_of_a_superseded_certificate_only_is_not_a_member() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    let path = "docs/a";
    f.accept(
        ObjectKind::KeyState,
        &f.key_state(path, "create", 1, "active", 1),
    )
    .await
    .unwrap();
    // The reshare to four members leaves this node out.
    let (x, y) = (ident(), ident());
    let successor = spliced_body(
        1,
        &f.network,
        &[&f.others[0].did, &f.others[1].did, &x.did, &y.did],
        Some(&f.body),
    );
    f.accept(ObjectKind::Cert, &f.cert_of(&successor))
        .await
        .unwrap();
    // Not yet activated: the genesis is still current.
    f.accept(
        ObjectKind::KeyState,
        &f.key_state(path, "block", 2, "blocked", 1),
    )
    .await
    .unwrap();
    f.accept(
        ObjectKind::Activation,
        &f.activation_of(&successor, &[&x, &y]),
    )
    .await
    .unwrap();
    assert_eq!(
        unavailable(
            f.accept(
                ObjectKind::KeyState,
                &f.key_state(path, "unblock", 3, "active", 1)
            )
            .await
        ),
        "not_a_member"
    );
    assert_eq!(f.row(path).await.state_seq, 2);
}

// ------------------------------------------------------- more merge cases

#[tokio::test]
async fn a_block_before_its_create_leaves_the_key_blocked() {
    let f = Fixture::activated(Owner::Key(ident())).await;
    let path = "docs/a";
    f.accept(
        ObjectKind::KeyState,
        &f.key_state(path, "block", 2, "blocked", 1),
    )
    .await
    .unwrap();
    let create = f
        .accept(
            ObjectKind::KeyState,
            &f.key_state(path, "create", 1, "active", 1),
        )
        .await
        .unwrap();
    assert!(create.new);
    assert_eq!(
        create.key,
        Some(KeyView {
            path: path.to_string(),
            state_seq: 2,
            state: "blocked".to_string(),
            key_version: 1,
        })
    );
    assert!(!f.row(path).await.conflict);
}

#[tokio::test]
async fn statements_with_one_effect_at_one_state_seq_agree_in_any_order() {
    let owner = ident();
    let mut rows = Vec::new();
    for reversed in [false, true] {
        let owner = Ident {
            jwk: owner.jwk.clone(),
            did: owner.did.clone(),
            vm: owner.vm.clone(),
        };
        let f = Fixture::activated(Owner::Key(owner)).await;
        // Two encodings of one effect: another label, the same state.
        let a = f.key_state("docs/a", "create", 4, "active", 2);
        let b = f.key_state("docs/a", "unblock", 4, "active", 2);
        let order = if reversed { [&b, &a] } else { [&a, &b] };
        f.accept(ObjectKind::KeyState, order[0]).await.unwrap();
        f.accept(ObjectKind::KeyState, order[1]).await.unwrap();
        let row = f.row("docs/a").await;
        assert_eq!(row.statement_cid, object_cid(&a).min(object_cid(&b)));
        assert_eq!(f.faults().await, 0);
        rows.push((
            row.state,
            row.state_seq,
            row.key_version,
            row.statement_cid,
            row.conflict,
        ));
    }
    assert_eq!(rows[0], rows[1]);
    assert_eq!((rows[0].0.as_str(), rows[0].4), ("active", false));
}

// ------------------------------------- revocations: GB-3, §4.1, selectors

#[tokio::test]
async fn a_former_grant_holder_backdating_into_the_grant_window_is_accepted() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let holder = ident();
    let t = now();
    let target = format!("urn:cid:{}", cid_of(&c.leaf));
    // The owner's grant ended an hour ago; the holder dates its revocation
    // inside it. Accepted on purpose (GB-3 residual): it only removes access.
    let grant = ucan(
        &owner,
        &holder.did,
        &[(&target, REVOKE_ABILITY)],
        vec![],
        None,
        t - 3_600,
    );
    let object = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&grant)], t - 7_200, t - 7_000),
        &[&c.leaf, &c.root, &grant],
    );
    f.accept(ObjectKind::Revocation, &object).await.unwrap();
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[tokio::test]
async fn a_revocation_of_the_control_grant_does_not_change_acceptance() {
    use sea_orm::ActiveModelTrait;
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let holder = ident();
    let t = now();
    let target = format!("urn:cid:{}", cid_of(&c.leaf));
    let grant = ucan(
        &owner,
        &holder.did,
        &[(&target, REVOKE_ABILITY)],
        vec![],
        None,
        t + 600,
    );
    let first = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&grant)], t, t + 300),
        &[&c.leaf, &c.root, &grant],
    );
    f.accept(ObjectKind::Revocation, &first).await.unwrap();
    // The owner then revokes the grant through the node's own graph.
    revocation::ActiveModel {
        id: Set(hash(b"grant-revocation")),
        revoker: Set(owner.did.clone()),
        revoked: Set(hash(grant.as_bytes())),
        serialization: Set(b"grant-revocation".to_vec()),
        revoked_at: Set(Some(OffsetDateTime::now_utc())),
    }
    .insert(&f.db)
    .await
    .unwrap();
    // Another revocation the holder made under the grant is still accepted.
    let second = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&grant)], t - 60, t + 300),
        &[&c.leaf, &c.root, &grant],
    );
    assert!(f.accept(ObjectKind::Revocation, &second).await.unwrap().new);
    assert_eq!(revocations(&f.db, &c.leaf).await, 2);
}

#[tokio::test]
async fn a_revocation_arriving_after_its_own_exp_is_accepted() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let t = now();
    // Signed for a 5-minute window that ended 10 minutes ago.
    let object = revocation_object(
        &revoke(&c.a, &c.leaf, vec![], t - 900, t - 600),
        &[&c.leaf, &c.root],
    );
    f.accept(ObjectKind::Revocation, &object).await.unwrap();
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[tokio::test]
async fn an_ancestor_revoked_first_refuses_the_readers_chain_posted_later() {
    let (f, owner) = did_key_owner().await;
    let (a, reader) = (ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let root = ucan(
        &owner,
        &a.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![],
        None,
        t + 3_600,
    );
    let object = revocation_object(&revoke(&owner, &root, vec![], t, t + 300), &[&root]);
    f.accept(ObjectKind::Revocation, &object).await.unwrap();

    let readers = ucan(
        &a,
        &reader.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&root)],
        None,
        t + 3_600,
    );
    let posted = Delegation::from_header_ser::<TinyCloudDelegation>(&readers).unwrap();
    let result = delegation::process_with(&f.db, &posted, None, false, true, None, false).await;
    assert!(
        matches!(
            result,
            Err(delegation::Error::InvalidDelegation(
                delegation::DelegationError::ParentRevoked(_)
            ))
        ),
        "{result:?}"
    );
}

/// The TC-405 selector caveat: a UCAN capability's caveat object.
fn selector(kind: &str, value: Option<&str>) -> BTreeMap<String, Value> {
    let mut selector = BTreeMap::from([
        ("type".to_string(), json!("xyz.tinycloud.resource/selector")),
        ("kind".to_string(), json!(kind)),
    ]);
    if let Some(value) = value {
        selector.insert("value".to_string(), json!(value));
    }
    selector
}

#[tokio::test]
async fn an_attached_chain_follows_the_selector_containment_rule() {
    let (f, owner) = did_key_owner().await;
    let t = now();
    let urn = f.key_urn("docs/a");
    let cases = [
        // A selector only the child carries.
        (BTreeMap::new(), selector("exact", Some("docs/a")), false),
        // Identical but malformed selectors.
        (selector("exact", None), selector("exact", None), false),
        // A contained selector.
        (
            selector("prefix", Some("docs")),
            selector("exact", Some("docs/a")),
            true,
        ),
    ];
    for (parent, child, contained) in cases {
        let (a, b) = (ident(), ident());
        let root = ucan_with_caveat(
            &owner,
            &a.did,
            &[(&urn, DECRYPT_ACTION)],
            parent,
            vec![],
            vec![],
            None,
            1_000,
        );
        let leaf = ucan_with_caveat(
            &a,
            &b.did,
            &[(&urn, DECRYPT_ACTION)],
            child,
            vec![],
            vec![cid_of(&root)],
            None,
            1_000,
        );
        let object = revocation_object(&revoke(&a, &leaf, vec![], t, t + 300), &[&leaf, &root]);
        let result = f.accept(ObjectKind::Revocation, &object).await;
        if contained {
            result.unwrap();
            assert_eq!(revocations(&f.db, &leaf).await, 1);
        } else {
            assert_eq!(refusal(result), "chain_attenuation");
        }
    }
}

// ----------------------------- the attached chain meets /delegate admission

/// Owner → A carrying `root_caps` and `facts`, then A → B `decrypt`, which
/// A revokes with both attached; nothing may be stored.
async fn assert_unstorable(
    f: &Fixture,
    owner: &Ident,
    root_caps: &[(&str, &str)],
    facts: Vec<Value>,
) {
    let (a, b) = (ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let root = ucan_with_caveat(
        owner,
        &a.did,
        root_caps,
        BTreeMap::new(),
        facts,
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
    let object = revocation_object(&revoke(&a, &leaf, vec![], t, t + 300), &[&leaf, &root]);
    assert_eq!(
        refusal(f.accept(ObjectKind::Revocation, &object).await),
        "delegation_unstorable"
    );
    assert_eq!(delegation::Entity::find().count(&f.db).await.unwrap(), 0);
    assert_eq!(revocations(&f.db, &leaf).await, 0);
}

#[tokio::test]
async fn an_attached_key_delete_grant_is_refused_and_not_stored() {
    let (f, owner) = did_key_owner().await;
    let urn = f.key_urn("docs/a");
    assert_unstorable(
        &f,
        &owner,
        &[
            (&urn, DECRYPT_ACTION),
            (&urn, "tinycloud.encryption/key.delete"),
        ],
        vec![],
    )
    .await;
}

#[tokio::test]
async fn an_attached_child_of_a_terminal_grant_is_refused_and_not_stored() {
    let (f, owner) = did_key_owner().await;
    let urn = f.key_urn("docs/a");
    assert_unstorable(
        &f,
        &owner,
        &[(&urn, DECRYPT_ACTION)],
        vec![Value::Object(
            [(
                crate::util::DelegationMode::FACT_KEY.to_string(),
                json!("terminal"),
            )]
            .into_iter()
            .collect(),
        )],
    )
    .await;
}

#[tokio::test]
async fn a_key_grant_refused_only_for_lacking_named_keys_faults_no_peer() {
    let (mut f, owner) = did_key_owner().await;
    f.set = f.set.clone().with_delegation_rules(false, false);
    let (a, b) = (ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let root = ucan(
        &owner,
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
    let object = revocation_object(&revoke(&a, &leaf, vec![], t, t + 300), &[&leaf, &root]);
    let result = f
        .set
        .accept(
            &f.network,
            ObjectKind::Revocation,
            &object,
            Source::Peer(PEER),
        )
        .await;
    assert_eq!(unavailable(result), "delegation_unstorable_here");
    assert_eq!(f.faults().await, 0);
    assert_eq!(delegation::Entity::find().count(&f.db).await.unwrap(), 0);
    assert_eq!(revocations(&f.db, &leaf).await, 0);
    let held = threshold_set_object::Entity::find()
        .filter(threshold_set_object::Column::Kind.eq(ObjectKind::Revocation.as_str()))
        .count(&f.db)
        .await
        .unwrap();
    assert_eq!(held, 0);
}

#[tokio::test]
async fn an_attached_control_grant_to_a_third_party_is_refused() {
    let (f, owner) = did_key_owner().await;
    let c = chain(&f, &owner);
    let holder = ident();
    // TC-3150: the target's delegator may hand revocation only to the
    // target's delegatee.
    let grant = ucan(
        &c.a,
        &holder.did,
        &[(&format!("urn:cid:{}", cid_of(&c.leaf)), REVOKE_ABILITY)],
        vec![],
        None,
        1_000,
    );
    let object = revocation_object(
        &revoke(&holder, &c.leaf, vec![cid_of(&grant)], 900, 950),
        &[&c.leaf, &c.root, &grant],
    );
    // Refused as MissingParents, which reads this node's graph: no fault.
    assert_eq!(
        unavailable(f.accept(ObjectKind::Revocation, &object).await),
        "delegation_unstorable_here"
    );
    assert_eq!(delegation::Entity::find().count(&f.db).await.unwrap(), 0);
    // To the target's delegatee it is admitted.
    let grant = ucan(
        &c.a,
        &c.b.did,
        &[(&format!("urn:cid:{}", cid_of(&c.leaf)), REVOKE_ABILITY)],
        vec![],
        None,
        1_000,
    );
    let object = revocation_object(
        &revoke(&c.b, &c.leaf, vec![cid_of(&grant)], 900, 950),
        &[&c.leaf, &c.root, &grant],
    );
    f.accept(ObjectKind::Revocation, &object).await.unwrap();
    assert_eq!(revocations(&f.db, &c.leaf).await, 1);
}

#[tokio::test]
async fn a_certificate_naming_other_nodes_only_is_not_held() {
    let f = Fixture::did_key().await;
    let x = ident();
    let body = spliced_body(
        0,
        &f.network,
        &[&f.others[0].did, &f.others[1].did, &x.did],
        None,
    );
    assert_eq!(
        unavailable(f.accept(ObjectKind::Cert, &f.cert_of(&body)).await),
        "not_a_member"
    );
    assert!(f.set.chain(&f.network).await.unwrap().is_empty());
}

// ------------------------------------------------------------- joiners

/// A network this node joins at the 3-of-4 reshare: the genesis names `x`
/// and `f.others`, its successor `f.others`, `y` and this node.
fn joined(f: &Fixture, x: &Ident, y: &Ident) -> (CertificateBody, CertificateBody) {
    let genesis = spliced_body(
        0,
        &f.network,
        &[&x.did, &f.others[0].did, &f.others[1].did],
        None,
    );
    let successor = spliced_body(
        1,
        &f.network,
        &[&f.others[0].did, &f.others[1].did, &y.did, f.set.node_did()],
        Some(&genesis),
    );
    (genesis, successor)
}

#[tokio::test]
async fn a_node_joining_at_a_reshare_holds_the_chain_back_to_its_genesis() {
    let f = Fixture::did_key().await;
    let (x, y) = (ident(), ident());
    let (genesis, successor) = joined(&f, &x, &y);
    f.accept(ObjectKind::Cert, &f.cert_of(&successor))
        .await
        .unwrap();
    f.accept(ObjectKind::Cert, &f.cert_of(&genesis))
        .await
        .unwrap();
    f.accept(ObjectKind::Activation, &f.activation_of(&genesis, &[&x]))
        .await
        .unwrap();
    f.accept(ObjectKind::Activation, &f.activation_of(&successor, &[&y]))
        .await
        .unwrap();
    f.set.require_member(&f.network).await.unwrap();
}

#[tokio::test]
async fn a_joiner_holds_the_genesis_once_it_holds_the_successor() {
    let f = Fixture::did_key().await;
    let (x, y) = (ident(), ident());
    let (genesis, successor) = joined(&f, &x, &y);
    assert_eq!(
        unavailable(f.accept(ObjectKind::Cert, &f.cert_of(&genesis)).await),
        "not_a_member"
    );
    f.accept(ObjectKind::Cert, &f.cert_of(&successor))
        .await
        .unwrap();
    assert!(
        f.accept(ObjectKind::Cert, &f.cert_of(&genesis))
            .await
            .unwrap()
            .new
    );
    f.accept(ObjectKind::Activation, &f.activation_of(&genesis, &[&x]))
        .await
        .unwrap();
    f.accept(ObjectKind::Activation, &f.activation_of(&successor, &[&y]))
        .await
        .unwrap();
    f.set.require_member(&f.network).await.unwrap();
}

#[tokio::test]
async fn a_certificate_preceding_nothing_held_is_not_held() {
    let f = Fixture::did_key().await;
    let (x, y) = (ident(), ident());
    let (_, successor) = joined(&f, &x, &y);
    f.accept(ObjectKind::Cert, &f.cert_of(&successor))
        .await
        .unwrap();
    let unrelated = spliced_body(
        0,
        &f.network,
        &[&f.others[0].did, &x.did, &f.others[1].did],
        None,
    );
    assert_eq!(
        unavailable(f.accept(ObjectKind::Cert, &f.cert_of(&unrelated)).await),
        "not_a_member"
    );
}

// ------------------------------------------------------------ sign-outs

/// Sol's sequence: owner → O → D is on members A (`f`) and B; B signs O
/// out; O's control grant to D reaches B only inside D's revocation of
/// O → D (`object`).
struct SignedOut {
    f: Fixture,
    b_db: DatabaseConnection,
    b: ThresholdSet,
    d: Ident,
    target: String,
    grant: String,
    object: Vec<u8>,
}

async fn signed_out() -> SignedOut {
    let (f, owner) = did_key_owner().await;
    let b_db = fresh_db().await;
    let b =
        ThresholdSet::new(b_db.clone(), node_keypair(), None).with_delegation_rules(false, true);
    for (kind, bytes) in [
        (ObjectKind::Cert, f.cert()),
        (ObjectKind::Activation, f.activation()),
    ] {
        b.accept(&f.network, kind, &bytes, Source::Client)
            .await
            .unwrap();
    }
    let (o, d) = (ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let root = ucan(
        &owner,
        &o.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![],
        None,
        t + 3_600,
    );
    let target = ucan(
        &o,
        &d.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&root)],
        None,
        t + 3_600,
    );
    for db in [&f.db, &b_db] {
        for header in [&root, &target] {
            let posted = Delegation::from_header_ser::<TinyCloudDelegation>(header).unwrap();
            delegation::process_with(db, &posted, None, false, true, None, false)
                .await
                .unwrap();
        }
    }
    let retire = crate::models::session_retire::retire(
        &b_db,
        &o.did,
        OffsetDateTime::now_utc(),
        time::Duration::days(1),
    )
    .await
    .unwrap();
    assert!(retire.recorded());
    let grant = ucan(
        &o,
        &d.did,
        &[(&format!("urn:cid:{}", cid_of(&target)), REVOKE_ABILITY)],
        vec![],
        None,
        t + 3_600,
    );
    let object = revocation_object(
        &revoke(&d, &target, vec![cid_of(&grant)], t, t + 300),
        &[&target, &root, &grant],
    );
    SignedOut {
        f,
        b_db,
        b,
        d,
        target,
        grant,
        object,
    }
}

#[tokio::test]
async fn a_revocation_carrying_a_signed_out_issuers_grant_converges_and_grants_nothing() {
    use crate::models::{
        invocation::{self, InvocationError},
        revocation::{control_proof_decision, ControlAction, ControlProofDecision},
    };
    let s = signed_out().await;
    let network = &s.f.network;
    for set in [&s.f.set, &s.b] {
        set.accept(network, ObjectKind::Revocation, &s.object, Source::Client)
            .await
            .unwrap();
    }
    for db in [&s.f.db, &s.b_db] {
        assert_eq!(revocations(db, &s.target).await, 1);
    }
    let grant = hash(s.grant.as_bytes());
    let on_a = delegation::Entity::find_by_id(grant).one(&s.f.db).await;
    assert!(on_a.unwrap().is_some());
    let on_b = delegation::Entity::find_by_id(grant).one(&s.b_db).await;
    assert!(on_b.unwrap().is_none());

    // No control proof on B rests on it; A, which holds it, has one.
    let target = hash(s.target.as_bytes());
    let proof = [cid_of(&s.grant)];
    for action in [
        ControlAction::Revoke,
        ControlAction::Status,
        ControlAction::Renew,
    ] {
        let decision = control_proof_decision(&s.b_db, &s.d.did, &proof, action, &target)
            .await
            .unwrap();
        assert!(matches!(decision, ControlProofDecision::Denied));
    }
    let decision =
        control_proof_decision(&s.f.db, &s.d.did, &proof, ControlAction::Revoke, &target)
            .await
            .unwrap();
    assert!(matches!(decision, ControlProofDecision::Scoped(_)));

    // D invoking under it on B.
    let invocation = ucan(
        &s.d,
        network.owner_did(),
        &[(&s.f.key_urn("docs/a"), DECRYPT_ACTION)],
        proof.to_vec(),
        None,
        now() + 300,
    );
    let info = crate::util::InvocationInfo::try_from(
        tinycloud_auth::authorization::TinyCloudInvocation::decode(&invocation).unwrap(),
    )
    .unwrap();
    let result = invocation::verify_and_authorize(&s.b_db, &info, OffsetDateTime::now_utc()).await;
    assert!(
        matches!(
            result,
            Err(invocation::Error::InvalidInvocation(
                InvocationError::MissingParents
            ))
        ),
        "{result:?}"
    );
    // Posted to B afterwards, as at /delegate, it is refused for the sign-out.
    let posted = Delegation::from_header_ser::<TinyCloudDelegation>(&s.grant).unwrap();
    let result = delegation::process_with(&s.b_db, &posted, None, false, true, None, false).await;
    assert!(
        matches!(
            result,
            Err(delegation::Error::InvalidDelegation(
                delegation::DelegationError::SessionRetired(_)
            ))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_signed_out_issuers_grant_carried_for_anything_else_is_refused() {
    let s = signed_out().await;
    let grant = Delegation::from_header_ser::<TinyCloudDelegation>(&s.grant).unwrap();
    let result = delegation::process_carried(
        &s.b_db,
        &grant,
        None,
        false,
        true,
        delegation::CarriedFor::Other,
    )
    .await;
    assert!(
        matches!(
            result,
            Err(delegation::Error::InvalidDelegation(
                delegation::DelegationError::SessionRetired(_)
            ))
        ),
        "{result:?}"
    );
    assert_eq!(delegation::Entity::find().count(&s.b_db).await.unwrap(), 2);
}

// --------------------------------------------------------- equivocation

/// The genesis of `members` with vector case `material`'s master public
/// key, commitments and transcript: another key for the same network.
fn genesis_with_material(
    material: usize,
    network: &NetworkId,
    members: &[&str],
) -> CertificateBody {
    fn public_section(v: &[u8]) -> std::ops::Range<usize> {
        let u16_at = |at: usize| u16::from_be_bytes(v[at..at + 2].try_into().unwrap());
        let skip_lp =
            |at: usize| at + 4 + u32::from_be_bytes(v[at..at + 4].try_into().unwrap()) as usize;
        let mut at = skip_lp(skip_lp(1)) + 22;
        let count = u16_at(at);
        at += 2;
        for _ in 0..count {
            at = skip_lp(at + 2);
        }
        at..at + 96 + 2 + 96 * usize::from(u16_at(at + 96)) + 32
    }
    let vectors: Value = serde_json::from_str(CHAIN).unwrap();
    let other = hex::decode(
        vectors["cases"][material]["inputs"]["certificate"]["body"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let mut out = spliced_body(0, network, members, None).encode();
    let (mine, theirs) = (public_section(&out), public_section(&other));
    out.splice(mine, other[theirs].iter().copied());
    CertificateBody::decode(&out).unwrap()
}

async fn fault_rows(db: &DatabaseConnection) -> Vec<(String, String, String)> {
    threshold_fault::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|fault| (fault.source_did, fault.object_cid, fault.reason))
        .collect()
}

#[tokio::test]
async fn equivocated_geneses_leave_every_member_without_a_current_certificate() {
    let f = Fixture::did_key().await;
    let members = [
        f.set.node_did(),
        f.others[0].did.as_str(),
        f.others[1].did.as_str(),
    ];
    let second = genesis_with_material(6, &f.network, &members);
    assert_ne!(
        second.public_material().master_public_key().encode(),
        f.body.public_material().master_public_key().encode()
    );
    let geneses = [
        (f.cert(), f.activation()),
        (f.cert_of(&second), f.activation_of(&second, &[])),
    ];
    let b_db = fresh_db().await;
    let b = ThresholdSet::new(b_db.clone(), node_keypair(), None);
    // A takes the first genesis first, B the second.
    for (set, order) in [(&f.set, [0, 1]), (&b, [1, 0])] {
        for index in order {
            let (cert, activation) = &geneses[index];
            set.accept(&f.network, ObjectKind::Cert, cert, Source::Client)
                .await
                .unwrap();
            set.accept(
                &f.network,
                ObjectKind::Activation,
                activation,
                Source::Client,
            )
            .await
            .unwrap();
        }
    }
    let lowest = [object_cid(&geneses[0].1), object_cid(&geneses[1].1)]
        .into_iter()
        .min()
        .unwrap();
    let mut held = Vec::new();
    for (db, set) in [(&f.db, &f.set), (&b_db, &b)] {
        let mut cids: Vec<String> = set
            .chain(&f.network)
            .await
            .unwrap()
            .into_iter()
            .map(|(_, cid, _)| cid)
            .collect();
        cids.sort();
        assert_eq!(cids.len(), 4);
        held.push(cids);
        assert_eq!(
            fault_rows(db).await,
            vec![(
                f.network.owner_did().to_string(),
                lowest.clone(),
                "genesis_conflict".to_string()
            )]
        );
        assert!(matches!(
            set.require_member(&f.network).await,
            Err(AcceptError::Unavailable("not_a_member"))
        ));
    }
    assert_eq!(held[0], held[1]);
}

// ------------------------------------------------------------ round 4

#[tokio::test]
async fn a_revoked_delegation_kept_out_of_the_graph_is_refused_when_posted_later() {
    use crate::models::{
        invocation::{self, InvocationError},
        session_retire,
    };
    let (f, owner) = did_key_owner().await;
    let (o, d) = (ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let root = ucan(
        &owner,
        &o.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![],
        None,
        t + 3_600,
    );
    let posted = Delegation::from_header_ser::<TinyCloudDelegation>(&root).unwrap();
    delegation::process_with(&f.db, &posted, None, false, true, None, false)
        .await
        .unwrap();
    let retire = session_retire::retire(
        &f.db,
        &o.did,
        OffsetDateTime::now_utc(),
        time::Duration::days(1),
    )
    .await
    .unwrap();
    assert!(retire.recorded());
    // O → D, never posted here, revoked by O with it attached.
    let target = ucan(
        &o,
        &d.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&root)],
        None,
        t + 3_600,
    );
    let object = revocation_object(&revoke(&o, &target, vec![], t, t + 300), &[&target, &root]);
    assert!(f.accept(ObjectKind::Revocation, &object).await.unwrap().new);
    assert_eq!(revocations(&f.db, &target).await, 0);

    // The sign-out expires; D posts O → D.
    session_retire::Entity::delete_many()
        .exec(&f.db)
        .await
        .unwrap();
    let posted = Delegation::from_header_ser::<TinyCloudDelegation>(&target).unwrap();
    let result = delegation::process_with(&f.db, &posted, None, false, true, None, false).await;
    assert!(
        matches!(
            result,
            Err(delegation::Error::InvalidDelegation(
                delegation::DelegationError::Revoked(_)
            ))
        ),
        "{result:?}"
    );
    let invocation = ucan(
        &d,
        f.network.owner_did(),
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&target)],
        None,
        now() + 300,
    );
    let info = crate::util::InvocationInfo::try_from(
        tinycloud_auth::authorization::TinyCloudInvocation::decode(&invocation).unwrap(),
    )
    .unwrap();
    let result = invocation::verify_and_authorize(&f.db, &info, OffsetDateTime::now_utc()).await;
    assert!(
        matches!(
            result,
            Err(invocation::Error::InvalidInvocation(
                InvocationError::MissingParents
            ))
        ),
        "{result:?}"
    );
}

fn pass_hook<F>(hook: F) -> PassHook
where
    F: for<'a> Fn(&'a DatabaseTransaction) -> futures::future::BoxFuture<'a, ()>
        + Send
        + Sync
        + 'static,
{
    std::sync::Arc::new(hook)
}

#[tokio::test]
async fn a_sign_out_between_admission_passes_keeps_that_link_out_too() {
    use crate::models::session_retire;
    let (mut f, owner) = did_key_owner().await;
    let (o, p, d) = (ident(), ident(), ident());
    let t = now();
    let urn = f.key_urn("docs/a");
    let grant = |to: &Ident| {
        ucan(
            &owner,
            &to.did,
            &[(&urn, DECRYPT_ACTION)],
            vec![],
            None,
            t + 3_600,
        )
    };
    let (to_p, to_o) = (grant(&p), grant(&o));
    for header in [&to_p, &to_o] {
        let posted = Delegation::from_header_ser::<TinyCloudDelegation>(header).unwrap();
        delegation::process_with(&f.db, &posted, None, false, true, None, false)
            .await
            .unwrap();
    }
    let retire = session_retire::retire(
        &f.db,
        &o.did,
        OffsetDateTime::now_utc(),
        time::Duration::days(1),
    )
    .await
    .unwrap();
    assert!(retire.recorded());
    // owner → P (stored) → O (P's link, new here) → D (O's, new here).
    let link = ucan(
        &p,
        &o.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&to_p)],
        None,
        t + 3_600,
    );
    let target = ucan(
        &o,
        &d.did,
        &[(&urn, DECRYPT_ACTION)],
        vec![cid_of(&link)],
        None,
        t + 3_600,
    );
    // The first pass sets O → D aside; P signs out before the next.
    let signing_out = p.did.clone();
    f.set = f.set.clone().with_between_passes(pass_hook(move |tx| {
        let did = signing_out.clone();
        Box::pin(async move {
            session_retire::retire_in(
                tx,
                &did,
                OffsetDateTime::now_utc(),
                time::Duration::days(1),
                None,
            )
            .await
            .unwrap();
        })
    }));
    let object = revocation_object(
        &revoke(&o, &target, vec![], t, t + 300),
        &[&target, &link, &to_p],
    );
    f.accept(ObjectKind::Revocation, &object).await.unwrap();
    let stored = delegation::Entity::find_by_id(hash(link.as_bytes()))
        .one(&f.db)
        .await
        .unwrap();
    assert!(stored.is_none());
    assert!(
        revocation_tombstone::is_tombstoned(&f.db, &[hash(target.as_bytes())])
            .await
            .unwrap()
    );
    assert!(
        !revocation_tombstone::is_tombstoned(&f.db, &[hash(link.as_bytes())])
            .await
            .unwrap()
    );
}

fn node_key(seed: u8) -> Keypair {
    crate::keys::StaticSecret::new(vec![seed; 32])
        .unwrap()
        .node_keypair()
}

#[tokio::test]
async fn overlapping_equivocated_geneses_fail_closed_on_every_member_holding_either() {
    let f = Fixture::did_key().await;
    let (z_key, w_key) = (node_key(0x44), node_key(0x55));
    let (z_db, w_db) = (fresh_db().await, fresh_db().await);
    let z = ThresholdSet::new(z_db.clone(), z_key.clone(), None);
    let w = ThresholdSet::new(w_db.clone(), w_key.clone(), None);
    let [x, y] = &f.others;
    // G1 = {X, Y, Z}, G2 = {X, Y, W}, under different keys.
    let g1 = spliced_body(0, &f.network, &[&x.did, &y.did, z.node_did()], None);
    let g2 = genesis_with_material(6, &f.network, &[&x.did, &y.did, w.node_did()]);
    let first = (f.cert_of(&g1), f.activation_with(&g1, &[&z_key], &[]));
    let second = (f.cert_of(&g2), f.activation_with(&g2, &[&w_key], &[]));
    let lowest = [object_cid(&first.1), object_cid(&second.1)]
        .into_iter()
        .min()
        .unwrap();
    // Each takes its own genesis, then the other, as from X or Y.
    for (set, own, other) in [(&z, &first, &second), (&w, &second, &first)] {
        for (index, (cert, activation)) in [own, other].into_iter().enumerate() {
            set.accept(&f.network, ObjectKind::Cert, cert, Source::Client)
                .await
                .unwrap();
            set.accept(
                &f.network,
                ObjectKind::Activation,
                activation,
                Source::Client,
            )
            .await
            .unwrap();
            if index == 0 {
                set.require_member(&f.network).await.unwrap();
            }
        }
    }
    for (db, set, body) in [(&z_db, &z, &g1), (&w_db, &w, &g2)] {
        assert_eq!(
            fault_rows(db).await,
            vec![(
                f.network.owner_did().to_string(),
                lowest.clone(),
                "genesis_conflict".to_string()
            )]
        );
        assert!(matches!(
            set.require_member(&f.network).await,
            Err(AcceptError::Unavailable("not_a_member"))
        ));
        // N's rows are the own genesis's alone.
        let row = encryption_network::Entity::find_by_id(f.network.to_string())
            .one(db)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            row.public_key,
            body.public_material().master_public_key().encode().to_vec()
        );
        let mut members: Vec<String> = encryption_network_member::Entity::find()
            .all(db)
            .await
            .unwrap()
            .into_iter()
            .map(|member| member.node_id)
            .collect();
        members.sort();
        let mut named: Vec<String> = body
            .members()
            .iter()
            .map(|member| member.node.as_str().to_string())
            .collect();
        named.sort();
        assert_eq!(members, named);
    }
}

#[tokio::test]
async fn another_genesis_is_not_held_without_an_activated_one() {
    let f = Fixture::did_key().await;
    let x = ident();
    let other = spliced_body(
        0,
        &f.network,
        &[&x.did, &f.others[0].did, &f.others[1].did],
        None,
    );
    // This node's own genesis is held but not activated.
    f.accept(ObjectKind::Cert, &f.cert()).await.unwrap();
    assert_eq!(
        unavailable(f.accept(ObjectKind::Cert, &f.cert_of(&other)).await),
        "not_a_member"
    );
    f.accept(ObjectKind::Activation, &f.activation())
        .await
        .unwrap();
    // Held once it is, and never this node's network.
    f.accept(ObjectKind::Cert, &f.cert_of(&other))
        .await
        .unwrap();
    f.accept(ObjectKind::Activation, &f.activation_of(&other, &[&x]))
        .await
        .unwrap();
    assert!(f.set.require_member(&f.network).await.is_err());
    assert_eq!(
        encryption_network_member::Entity::find()
            .count(&f.db)
            .await
            .unwrap(),
        3
    );
}
