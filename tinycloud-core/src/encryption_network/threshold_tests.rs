//! Threshold network rows: refused while `threshold_v1` is off, served by the
//! threshold backend while it is on, and never by the one-of-one backend.
//! The key material is a real 2-of-3 network from the crate's DKG.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, ConnectOptions, Database, DatabaseConnection,
    EntityTrait, QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use time::OffsetDateTime;
use x25519_dalek::{PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::Zeroizing;

use tinycloud_auth::{
    authorization::Cid,
    multihash_codetable::{Code, MultihashDigest},
    resolver::DID_METHODS,
    ssi::{
        claims::jwt::NumericDate,
        dids::{DIDBuf, DIDURLBuf},
        jwk::{Algorithm, JWK},
        ucan::Payload,
    },
};
use tinycloud_threshold::ceremony::{
    round_closure_body, round_closure_preimage, CeremonyKind, CeremonyRecipient, CeremonyStatement,
    Decode,
};
use tinycloud_threshold::{
    combine, decrypt_derived_key, dkg_initial_transcript, dkg_start, unwrap_key,
    verify_certificate, verify_share, wrap_key, AfterBarrier, AuthorizedCeremony, CandidateShare,
    CeremonyHpkeSecretKey, CeremonyId, CertificateBody, ClosedRound, CombineError, DataKey,
    DecryptRequest, Did, DidSignatureVerifier, DkgAnswers, DkgComplaints, DkgDeal,
    DkgExtractionComplaints, DkgFeldman, DkgMessage, EncryptedKeyShare, Epoch, IbeIdentity,
    KeyPath, KeyShare, KeyVersion, MemberIndex, NetworkUrn, RekeyCounter, ShareError,
    SignatureError, SignedCertificate, SignedStatement, TranscriptHash, TransportSecretKey,
    TrustAnchor, VerifiedCertificate, WriteNonce,
};

use super::backend::{
    wrap_to_public_key, GeneratedKey, KeyBackend, KeyBackendError, KeySeed, KeyWrapContext,
    KeyWrapVersion, LocalOneOfOneBackend,
};
use super::canonical::{canonical_hash, canonical_json_bytes};
use super::delete_auth::{DeleteTarget, VerifiedOwnerDelete};
use super::deletion_ledger::DeletionLedger;
use super::key_id::KeyLocation;
use super::network_id::NetworkId;
use super::protocol::{
    DecryptFacts, DecryptInvocation, DecryptRequestBody, InvocationCapability, DECRYPT_ACTION,
    DECRYPT_REQUEST_TYPE,
};
use super::service::{
    CreateNetworkRequest, DecryptTarget, EncryptionService, EncryptionServiceError,
};
use super::threshold::{ShareSource, ShareSourceBackend, ShareSourceError, ThresholdBackendError};
use super::types::{KeyBackendKind, Threshold, ALG_X25519_AES256GCM};
use crate::encryption::ColumnEncryption;
use crate::keys::{public_key_to_did_key, Keypair, StaticSecret as NodeStaticSecret};
use crate::migrations::Migrator;
use crate::models::{
    encryption_ceremony, encryption_network, encryption_network_key, encryption_network_member,
};

const NODE_DID: &str = "did:key:z6MkNodeTest";
const NETWORK_NAME: &str = "default";
const KEY_PATH: &str = "apps/notes/k1";

// ---------------------------------------------------------------- 2-of-3 DKG

/// Ed25519 node keys for the owner (0) and the members (1..=3).
struct Signers(BTreeMap<Did, SigningKey>);

impl Signers {
    fn new() -> Self {
        Self(
            (0..=3u8)
                .map(|i| (Self::did(i), SigningKey::from_bytes(&[0x40 + i; 32])))
                .collect(),
        )
    }

    fn did(i: u8) -> Did {
        Did::new(format!("did:key:tc2226-node-{i}")).unwrap()
    }

    fn sign(&self, did: &Did, preimage: &[u8]) -> Vec<u8> {
        self.0[did].sign(preimage).to_bytes().to_vec()
    }

    fn sign_message(&self, member: u16, message: &DkgMessage) -> SignedStatement {
        SignedStatement {
            bytes: message.body().to_vec(),
            signature: self.sign(&Self::did(member as u8), &message.signing_preimage()),
        }
    }
}

impl DidSignatureVerifier for Signers {
    fn verify(&self, signer: &Did, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let key: VerifyingKey = self
            .0
            .get(signer)
            .ok_or(SignatureError::Invalid)?
            .verifying_key();
        let signature =
            ed25519_dalek::Signature::from_slice(signature).map_err(|_| SignatureError::Invalid)?;
        key.verify_strict(message, &signature)
            .map_err(|_| SignatureError::Invalid)
    }
}

/// The owner's side of the DKG: closes each round over the members' messages.
struct Relay<'a> {
    ceremony: &'a AuthorizedCeremony,
    signers: &'a Signers,
    previous: TranscriptHash,
}

impl Relay<'_> {
    fn close<M: Decode>(&mut self, round: u8, messages: Vec<SignedStatement>) -> ClosedRound<M> {
        let bytes = round_closure_body(self.ceremony, round, &self.previous, &messages).unwrap();
        let closure = SignedStatement {
            signature: self
                .signers
                .sign(&Signers::did(0), &round_closure_preimage(&bytes).unwrap()),
            bytes,
        };
        let closed = ClosedRound::<M>::verify(
            self.ceremony,
            round,
            &self.previous,
            &closure,
            &messages,
            self.signers,
        )
        .unwrap();
        self.previous = closed.transcript_hash();
        closed
    }
}

fn step<S, N>(
    signers: &Signers,
    states: Vec<(u16, S)>,
    advance: impl Fn(S) -> Result<(N, DkgMessage), tinycloud_threshold::Error>,
) -> (Vec<(u16, N)>, Vec<SignedStatement>) {
    let mut next = Vec::new();
    let mut messages = Vec::new();
    for (member, state) in states {
        let (state, message) = advance(state).unwrap();
        messages.push(signers.sign_message(member, &message));
        next.push((member, state));
    }
    (next, messages)
}

fn idx(i: u16) -> MemberIndex {
    MemberIndex::new(i).unwrap()
}

/// A 2-of-3 genesis network on `network`: its verified certificate and each
/// member's persisted share (`CandidateShare::to_bytes`).
struct ThresholdNetwork {
    certificate: VerifiedCertificate,
    shares: BTreeMap<u16, Zeroizing<[u8; 67]>>,
}

fn two_of_three(network: &NetworkUrn) -> ThresholdNetwork {
    let signers = Signers::new();
    let anchor = TrustAnchor {
        expected_owner: Signers::did(0),
        network: network.clone(),
    };
    let mut hpke_secrets = Vec::new();
    let mut recipients = Vec::new();
    for i in 1..=3u16 {
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut OsRng);
        hpke_secrets.push(secret);
        recipients.push(CeremonyRecipient {
            index: idx(i),
            node: Signers::did(i as u8),
            hpke_public_key: public.encode(),
        });
    }
    let statement = CeremonyStatement {
        kind: CeremonyKind::Genesis,
        id: CeremonyId::new([0x26; 32]),
        network: network.clone(),
        owner: Signers::did(0),
        current: None,
        threshold: tinycloud_threshold::Threshold::new(2, 3).unwrap(),
        rekey: RekeyCounter::new(0),
        epoch: Epoch::new(0),
        recipients,
    };
    let signed = SignedStatement {
        bytes: statement.encode(),
        signature: signers.sign(&statement.owner, &statement.signing_preimage()),
    };
    let ceremony = AuthorizedCeremony::verify_genesis(&anchor, &signed, &signers).unwrap();

    let mut relay = Relay {
        ceremony: &ceremony,
        signers: &signers,
        previous: dkg_initial_transcript(&ceremony),
    };
    let mut dealt = Vec::new();
    let mut r1 = Vec::new();
    for (i, secret) in (1..=3u16).zip(hpke_secrets) {
        let (state, message) = dkg_start(&ceremony, idx(i), secret, &mut OsRng).unwrap();
        r1.push(signers.sign_message(i, &message));
        dealt.push((i, state));
    }
    let closed1 = relay.close::<DkgDeal>(1, r1);
    let (complained, r2) = step(&signers, dealt, |s| s.complain(&closed1));
    let closed2 = relay.close::<DkgComplaints>(2, r2);
    let (answered, r3) = step(&signers, complained, |s| s.answer(&closed2));
    let closed3 = relay.close::<DkgAnswers>(3, r3);
    let (extracting, r4) = step(&signers, answered, |s| s.extract(&closed3));
    let closed4 = relay.close::<DkgFeldman>(4, r4);
    let (waiting, r5) = step(&signers, extracting, |s| s.extraction_complaints(&closed4));
    let closed5 = relay.close::<DkgExtractionComplaints>(5, r5);

    let mut candidates = BTreeMap::new();
    let mut output = None;
    for (i, state) in waiting {
        match state.after_barrier(&closed5).unwrap() {
            AfterBarrier::Finished(candidate, out) => {
                candidates.insert(i, candidate);
                output = Some(out);
            }
            AfterBarrier::Reconstruct(..) => panic!("an honest DKG finishes at the barrier"),
        }
    }
    let output = output.unwrap();
    let body =
        CertificateBody::genesis(&anchor, &ceremony, &output.public, &output.transcript_hash)
            .unwrap();
    let signed = SignedCertificate {
        owner_signature: signers.sign(&Signers::did(0), &body.owner_statement()),
        body,
    };
    let certificate = verify_certificate(&anchor, &signed, &signers).unwrap();
    let shares = candidates
        .into_iter()
        .map(|(i, candidate)| (i, candidate.to_bytes()))
        .collect();
    ThresholdNetwork {
        certificate,
        shares,
    }
}

/// One member's key material, reloaded on every read as a share store does.
struct MemberSource {
    certificate: VerifiedCertificate,
    share: Zeroizing<[u8; 67]>,
}

impl ShareSource for MemberSource {
    fn current_certificate(
        &self,
        network: &NetworkUrn,
    ) -> Result<Option<VerifiedCertificate>, ShareSourceError> {
        Ok((*network == self.certificate.anchor().network).then(|| self.certificate.clone()))
    }

    fn current_share(&self, network: &NetworkUrn) -> Result<Option<KeyShare>, ShareSourceError> {
        if *network != self.certificate.anchor().network {
            return Ok(None);
        }
        let candidate = CandidateShare::from_bytes(&*self.share)?;
        Ok(Some(KeyShare::bind(candidate, &self.certificate)?))
    }
}

// ------------------------------------------------------- service fixtures

/// Delegates to the one-of-one backend and counts every key operation.
struct CountingBackend {
    inner: LocalOneOfOneBackend,
    calls: Arc<AtomicUsize>,
}

impl CountingBackend {
    fn hit(&self) {
        self.calls.fetch_add(1, Ordering::SeqCst);
    }
}

impl KeyBackend for CountingBackend {
    fn kind(&self) -> KeyBackendKind {
        self.inner.kind()
    }

    fn generate(&self) -> Result<GeneratedKey, KeyBackendError> {
        self.hit();
        self.inner.generate()
    }

    fn unwrap(
        &self,
        sealed_private_key: &[u8],
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        self.hit();
        self.inner.unwrap(sealed_private_key, wrapped_key, context)
    }

    fn rewrap(
        &self,
        symmetric_key: &[u8],
        receiver_public_key: &[u8],
        context: &KeyWrapContext<'_>,
        version: KeyWrapVersion,
    ) -> Result<Vec<u8>, KeyBackendError> {
        self.hit();
        self.inner
            .rewrap(symmetric_key, receiver_public_key, context, version)
    }

    fn open_network_secret(
        &self,
        sealed_private_key: &[u8],
    ) -> Result<X25519StaticSecret, KeyBackendError> {
        self.hit();
        self.inner.open_network_secret(sealed_private_key)
    }

    fn derive_named_public_key(
        &self,
        network_secret: &X25519StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        self.hit();
        self.inner
            .derive_named_public_key(network_secret, canonical_urn, seed)
    }

    fn unwrap_named(
        &self,
        network_secret: &X25519StaticSecret,
        canonical_urn: &str,
        seed: Option<&KeySeed>,
        wrapped_key: &[u8],
        context: &KeyWrapContext<'_>,
    ) -> Result<Vec<u8>, KeyBackendError> {
        self.hit();
        self.inner
            .unwrap_named(network_secret, canonical_urn, seed, wrapped_key, context)
    }

    fn generate_seed(&self) -> Result<(KeySeed, Vec<u8>), KeyBackendError> {
        self.hit();
        self.inner.generate_seed()
    }

    fn open_seed(&self, sealed_seed: &[u8]) -> Result<KeySeed, KeyBackendError> {
        self.hit();
        self.inner.open_seed(sealed_seed)
    }
}

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect(ConnectOptions::new("sqlite::memory:".to_string()))
        .await
        .unwrap();
    Migrator::up(&db, None).await.unwrap();
    db
}

/// One node over a shared database: its service, a count of its one-of-one
/// backend's key operations, and its deletion ledger.
struct Node {
    service: EncryptionService,
    calls: Arc<AtomicUsize>,
    _ledger: tempfile::TempDir,
}

fn node(
    db: &DatabaseConnection,
    configure: impl FnOnce(EncryptionService) -> EncryptionService,
) -> Node {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = Arc::new(CountingBackend {
        inner: LocalOneOfOneBackend::new(ColumnEncryption::new([0xABu8; 32])),
        calls: calls.clone(),
    });
    let ledger = tempfile::tempdir().unwrap();
    let deletion_ledger =
        Arc::new(DeletionLedger::open(&ledger.path().join("ledger.jsonl")).unwrap());
    let service = EncryptionService::new(db.clone(), NODE_DID.to_string(), backend)
        .with_deletion_ledger(Some(deletion_ledger));
    Node {
        service: configure(service),
        calls,
        _ledger: ledger,
    }
}

impl Node {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

fn owner_keypair() -> Keypair {
    NodeStaticSecret::new(vec![0x11; 32])
        .unwrap()
        .node_keypair()
}

fn owner_did() -> String {
    public_key_to_did_key(owner_keypair().public())
}

fn network_id() -> NetworkId {
    NetworkId::new(owner_did(), NETWORK_NAME.to_string()).unwrap()
}

fn key_loc() -> KeyLocation {
    KeyLocation::new(&network_id(), KEY_PATH).unwrap()
}

/// Creates a one-of-one network, then marks its row `key_backend`. The row
/// keeps a sealed key the one-of-one backend could open, so only the backend
/// kind decides whether it is served. Returns the network's public key.
async fn network_row(
    service: &EncryptionService,
    db: &DatabaseConnection,
    key_backend: &str,
) -> Vec<u8> {
    let descriptor = service
        .create_one_of_one_network(CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        })
        .await
        .unwrap();
    set_key_backend(db, key_backend).await;
    descriptor.public_encryption_key
}

async fn set_key_backend(db: &DatabaseConnection, key_backend: &str) {
    encryption_network::ActiveModel {
        network_id: Set(network_id().to_string()),
        key_backend: Set(key_backend.to_string()),
        ..Default::default()
    }
    .update(db)
    .await
    .unwrap();
}

/// Every row a network operation can write.
#[derive(Debug, PartialEq)]
struct Rows {
    networks: Vec<encryption_network::Model>,
    members: Vec<encryption_network_member::Model>,
    keys: Vec<encryption_network_key::Model>,
    ceremonies: Vec<encryption_ceremony::Model>,
}

async fn rows(db: &DatabaseConnection) -> Rows {
    Rows {
        networks: encryption_network::Entity::find().all(db).await.unwrap(),
        members: encryption_network_member::Entity::find()
            .all(db)
            .await
            .unwrap(),
        keys: encryption_network_key::Entity::find()
            .all(db)
            .await
            .unwrap(),
        ceremonies: encryption_ceremony::Entity::find().all(db).await.unwrap(),
    }
}

/// A root decrypt request body and the facts that bind it.
struct RootDecrypt {
    body: Value,
    facts: DecryptFacts,
    receiver_secret: X25519StaticSecret,
    symmetric: Vec<u8>,
}

fn root_decrypt(network_public_key: &[u8]) -> RootDecrypt {
    let net = network_id();
    let symmetric = vec![0xCDu8; 32];
    let encrypted = STANDARD.encode(wrap_to_public_key(network_public_key, &symmetric).unwrap());
    let receiver_secret = X25519StaticSecret::random_from_rng(OsRng);
    let receiver = STANDARD.encode(PublicKey::from(&receiver_secret).as_bytes());
    let body = serde_json::to_value(DecryptRequestBody {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net.clone(),
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
        encrypted_symmetric_key: encrypted.clone(),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(encrypted.clone())),
        receiver_public_key: receiver.clone(),
        receiver_public_key_hash: canonical_hash(&Value::String(receiver.clone())),
        key_path: None,
    })
    .unwrap();
    let facts = DecryptFacts {
        ty: DECRYPT_REQUEST_TYPE.to_string(),
        target_node: NODE_DID.to_string(),
        network_id: net,
        body_hash: canonical_hash(&body),
        encrypted_symmetric_key_hash: canonical_hash(&Value::String(encrypted)),
        receiver_public_key_hash: canonical_hash(&Value::String(receiver)),
        key_path: None,
        alg: ALG_X25519_AES256GCM.to_string(),
        key_version: 1,
    };
    RootDecrypt {
        body,
        facts,
        receiver_secret,
        symmetric,
    }
}

/// An owner-signed legacy decrypt invocation.
fn signed_invocation(request: &RootDecrypt, nonce: &str) -> DecryptInvocation {
    let mut invocation = DecryptInvocation {
        issuer: owner_did(),
        audience: NODE_DID.to_string(),
        att: vec![InvocationCapability {
            with: network_id().to_string(),
            can: DECRYPT_ACTION.to_string(),
            nb: BTreeMap::new(),
        }],
        facts: request.facts.clone(),
        nonce: nonce.to_string(),
        not_before: None,
        exp: OffsetDateTime::now_utc().unix_timestamp() + 60,
        proof_cid: Vec::new(),
        sig: String::new(),
    };
    let message = canonical_json_bytes(&invocation.unsigned_payload());
    invocation.sig = STANDARD.encode(owner_keypair().sign(&message).unwrap());
    invocation
}

/// A native session-key decrypt invocation, as the node auth DAG passes it on.
fn session_invocation(request: &RootDecrypt) -> crate::util::InvocationInfo {
    let mut jwk = JWK::generate_ed25519().unwrap();
    jwk.algorithm = Some(Algorithm::EdDSA);
    let mut verification_method = DID_METHODS.generate(&jwk, "key").unwrap().to_string();
    let fragment = verification_method.rsplit_once(':').unwrap().1.to_string();
    verification_method.push('#');
    verification_method.push_str(&fragment);

    let resource: iri_string::types::UriString = network_id().to_string().parse().unwrap();
    let ability: tinycloud_auth::ucan_capabilities_object::Ability =
        DECRYPT_ACTION.to_string().try_into().unwrap();
    let mut attenuation = tinycloud_auth::ucan_capabilities_object::Capabilities::new();
    attenuation.with_actions(resource, std::iter::once((ability, [])));
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let payload = Payload {
        issuer: verification_method.parse::<DIDURLBuf>().unwrap(),
        audience: NODE_DID.parse::<DIDBuf>().unwrap(),
        not_before: None,
        expiration: NumericDate::try_from_seconds((now + 60) as f64).unwrap(),
        nonce: Some(format!("session-nonce-{now}")),
        facts: Some(vec![serde_json::to_value(&request.facts).unwrap()]),
        proof: vec![Cid::new_v1(
            0x55,
            Code::Blake3_256.digest(b"tc2226-session-delegation"),
        )],
        attenuation,
    };
    let invocation = payload.sign(Algorithm::EdDSA, &jwk).unwrap();
    crate::util::InvocationInfo::try_from(invocation).unwrap()
}

fn unwrap_rewrapped(secret: &X25519StaticSecret, wrapped_b64: &str) -> Vec<u8> {
    let wrapped = STANDARD.decode(wrapped_b64).unwrap();
    let mut peer = [0u8; 32];
    peer.copy_from_slice(&wrapped[..32]);
    let shared = secret.diffie_hellman(&PublicKey::from(peer));
    ColumnEncryption::new(*shared.as_bytes())
        .decrypt_legacy(&wrapped[32..])
        .unwrap()
}

fn assert_refused<T: std::fmt::Debug>(
    result: Result<T, EncryptionServiceError>,
    operation: &str,
    expected: fn(&EncryptionServiceError) -> bool,
) {
    match &result {
        Err(err) if expected(err) => {}
        other => panic!("{operation}: unexpected result {other:?}"),
    }
}

fn disabled(err: &EncryptionServiceError) -> bool {
    matches!(err, EncryptionServiceError::ThresholdBackendDisabled)
}

fn mismatch(err: &EncryptionServiceError) -> bool {
    matches!(err, EncryptionServiceError::KeyBackendMismatch)
}

fn no_key_material(err: &EncryptionServiceError) -> bool {
    matches!(
        err,
        EncryptionServiceError::Threshold(ThresholdBackendError::NoKeyMaterial)
    )
}

fn unauthorized_identity(err: &EncryptionServiceError) -> bool {
    matches!(
        err,
        EncryptionServiceError::Threshold(ThresholdBackendError::UnauthorizedIdentity)
    )
}

fn epoch_mismatch(err: &EncryptionServiceError) -> bool {
    matches!(
        err,
        EncryptionServiceError::Threshold(ThresholdBackendError::EpochMismatch)
    )
}

/// Every one-of-one decrypt and key operation on the network, each checked
/// with `expected`.
async fn assert_one_of_one_operations_refused(
    service: &EncryptionService,
    network_public_key: &[u8],
    expected: fn(&EncryptionServiceError) -> bool,
) {
    let net = network_id();
    let request = root_decrypt(network_public_key);
    let root = DecryptTarget::Root(net.clone());
    let session = session_invocation(&request);
    assert_refused(
        service
            .decrypt(
                &net,
                &signed_invocation(&request, "tc2226-legacy"),
                &request.body,
            )
            .await,
        "decrypt",
        expected,
    );
    assert_refused(
        service
            .validate_authorized_decrypt_request(&root, &session, &request.body)
            .await,
        "validate_authorized_decrypt_request",
        expected,
    );
    assert_refused(
        service
            .decrypt_authorized(&root, &session, &request.body)
            .await,
        "decrypt_authorized",
        expected,
    );
    assert_refused(
        service.create_key(&key_loc(), true).await,
        "create_key",
        expected,
    );
    // A deletable key never reads the network here, so ask for a
    // deterministic one.
    let deterministic = KeyLocation::new(&net, "docs/alpha").unwrap();
    assert_refused(
        service.public_key(&deterministic).await,
        "public_key",
        expected,
    );
    assert_refused(
        service.unwrap_named_key(&key_loc(), &[0u8; 96], 1).await,
        "unwrap_named_key",
        expected,
    );
    assert_refused(
        service
            .delete_keys(
                &net,
                &DeleteTarget::parse(&net, KEY_PATH).unwrap(),
                &VerifiedOwnerDelete {
                    owner: owner_did(),
                    nonce: "tc2226-delete".to_string(),
                    exp: 0,
                    auth_cid: "tc2226-delete-cid".to_string(),
                },
            )
            .await,
        "delete_keys",
        expected,
    );
}

/// The 2-of-3 network every flag-on test serves.
static THRESHOLD: LazyLock<ThresholdNetwork> =
    LazyLock::new(|| two_of_three(&NetworkUrn::new(network_id().to_string()).unwrap()));

/// A record-identity request for `key_path` at `version` under the network,
/// with the caller's transport secret and the identity.
fn threshold_request(
    key_path: &str,
    version: u64,
) -> (DecryptRequest, TransportSecretKey, IbeIdentity) {
    let identity = IbeIdentity::record(
        &NetworkUrn::new(network_id().to_string()).unwrap(),
        &KeyPath::new(key_path).unwrap(),
        KeyVersion::new(version),
        &WriteNonce::new([0x26; 16]),
    )
    .unwrap();
    let tsk = TransportSecretKey::generate(&mut OsRng);
    let request = DecryptRequest::new(
        &THRESHOLD.certificate.key_context(),
        identity.clone(),
        tsk.public_key(),
    )
    .unwrap();
    (request, tsk, identity)
}

/// Three member nodes over one database, each serving its own share of a
/// threshold network row.
async fn threshold_members(db: &DatabaseConnection) -> BTreeMap<u16, Node> {
    let mut members = BTreeMap::new();
    for (member, share) in &THRESHOLD.shares {
        let source = MemberSource {
            certificate: THRESHOLD.certificate.clone(),
            share: share.clone(),
        };
        let backend = Arc::new(ShareSourceBackend::new(Arc::new(source)));
        members.insert(
            *member,
            node(db, |service| {
                service
                    .with_threshold_v1(true)
                    .with_threshold_backend(backend)
            }),
        );
    }
    network_row(&members[&1].service, db, KeyBackendKind::Threshold.as_str()).await;
    members
}

// ------------------------------------------------------------------ tests

#[tokio::test]
async fn flag_off_refuses_a_threshold_row_and_never_reaches_the_one_of_one_backend() {
    let db = fresh_db().await;
    let node = node(&db, |service| service);
    let network_public_key =
        network_row(&node.service, &db, KeyBackendKind::Threshold.as_str()).await;
    let before = node.calls();
    assert!(before > 0, "the counting backend sees one-of-one work");

    let service = &node.service;
    let net = network_id();
    assert_refused(service.get_network(&net).await, "get_network", disabled);
    assert_refused(
        service
            .get_network_by_name(NETWORK_NAME, Some(&owner_did()))
            .await,
        "get_network_by_name with owner",
        disabled,
    );
    assert_refused(
        service.get_network_by_name(NETWORK_NAME, None).await,
        "get_network_by_name",
        disabled,
    );
    assert_one_of_one_operations_refused(service, &network_public_key, disabled).await;
    let (request, ..) = threshold_request(KEY_PATH, 1);
    assert_refused(
        service
            .threshold_derive_shares(&net, KEY_PATH, 1, request)
            .await,
        "threshold_derive_shares",
        disabled,
    );
    assert_refused(
        service.threshold_public_material(&net, Epoch::new(0)).await,
        "threshold_public_material",
        disabled,
    );
    assert_eq!(
        node.calls(),
        before,
        "a threshold row never reaches the one-of-one backend"
    );
}

#[tokio::test]
async fn an_unparseable_key_backend_is_still_served_by_the_one_of_one_backend() {
    let db = fresh_db().await;
    let node = node(&db, |service| service);
    let network_public_key = network_row(&node.service, &db, "not-a-backend").await;
    let before = node.calls();

    let descriptor = node.service.get_network(&network_id()).await.unwrap();
    assert_eq!(descriptor.key_backend, KeyBackendKind::LocalOneOfOne);
    let request = root_decrypt(&network_public_key);
    let verified = node
        .service
        .decrypt(
            &network_id(),
            &signed_invocation(&request, "tc2226-unparseable"),
            &request.body,
        )
        .await
        .unwrap();
    assert_eq!(
        unwrap_rewrapped(&request.receiver_secret, &verified.response.wrapped_key),
        request.symmetric
    );
    assert!(node.calls() > before);
}

#[tokio::test]
async fn flag_on_refuses_one_of_one_operations_on_a_threshold_row() {
    let db = fresh_db().await;
    let node = node(&db, |service| service.with_threshold_v1(true));
    let network_public_key =
        network_row(&node.service, &db, KeyBackendKind::Threshold.as_str()).await;
    let before = node.calls();

    let descriptor = node.service.get_network(&network_id()).await.unwrap();
    assert_eq!(descriptor.key_backend, KeyBackendKind::Threshold);
    assert_one_of_one_operations_refused(&node.service, &network_public_key, mismatch).await;
    assert_eq!(node.calls(), before);

    // No threshold backend is attached: this node holds no key material.
    let (request, ..) = threshold_request(KEY_PATH, 1);
    assert_refused(
        node.service
            .threshold_derive_shares(&network_id(), KEY_PATH, 1, request)
            .await,
        "threshold_derive_shares without a backend",
        no_key_material,
    );
}

#[tokio::test]
async fn threshold_operations_refuse_a_one_of_one_network() {
    let db = fresh_db().await;
    let node = node(&db, |service| service.with_threshold_v1(true));
    network_row(&node.service, &db, KeyBackendKind::LocalOneOfOne.as_str()).await;
    let (request, ..) = threshold_request(KEY_PATH, 1);
    assert_refused(
        node.service
            .threshold_derive_shares(&network_id(), KEY_PATH, 1, request)
            .await,
        "threshold_derive_shares",
        mismatch,
    );
    assert_refused(
        node.service
            .threshold_public_material(&network_id(), Epoch::new(0))
            .await,
        "threshold_public_material",
        mismatch,
    );
}

#[tokio::test]
async fn every_two_members_open_a_data_key_and_a_tampered_share_names_its_member() {
    let db = fresh_db().await;
    let members = threshold_members(&db).await;
    let before: Vec<usize> = members.values().map(Node::calls).collect();
    let net = network_id();
    let (request, tsk, identity) = threshold_request(KEY_PATH, 1);
    let public = THRESHOLD.certificate.public_key_set();

    let material = members[&1]
        .service
        .threshold_public_material(&net, Epoch::new(0))
        .await
        .unwrap();
    assert_eq!(material.context(), public.context());
    assert_eq!(
        material.master_public_key().encode(),
        public.master_public_key().encode()
    );

    let data_key = DataKey::new([0x5A; 32]);
    let ciphertext =
        wrap_key(public.master_public_key(), &identity, &data_key, &mut OsRng).unwrap();

    let mut issued = BTreeMap::new();
    for (member, node) in &members {
        let share = node
            .service
            .threshold_derive_shares(&net, KEY_PATH, 1, request.clone())
            .await
            .unwrap();
        assert_eq!(share.index(), idx(*member));
        verify_share(public, &request, &share).unwrap();
        issued.insert(*member, share);
    }

    for pair in [[1u16, 2], [1, 3], [2, 3]] {
        let shares: Vec<EncryptedKeyShare> = pair.iter().map(|m| issued[m].clone()).collect();
        let encrypted = combine(public, &request, &shares).unwrap();
        let derived = decrypt_derived_key(&encrypted, &tsk, public, &request).unwrap();
        let opened = unwrap_key(&derived, &identity, &ciphertext).unwrap();
        assert_eq!(opened.as_bytes(), data_key.as_bytes(), "members {pair:?}");
    }

    // Member 1's share carrying member 2's c3, and member 2's share relabelled
    // as member 1's: both decode, and both are blamed on member 1.
    let genuine = issued[&1].encode();
    let other = issued[&2].encode();
    let c3 = genuine.len() - 48;
    let mut wrong_c3 = genuine.clone();
    wrong_c3[c3..].copy_from_slice(&other[c3..]);
    let mut relabelled = other.clone();
    relabelled[1..3].copy_from_slice(&genuine[1..3]);
    for tampered in [wrong_c3, relabelled] {
        let tampered = EncryptedKeyShare::decode(&tampered).unwrap();
        assert_eq!(
            verify_share(public, &request, &tampered),
            Err(ShareError::Invalid { member: idx(1) })
        );
        let combined = combine(public, &request, &[tampered, issued[&3].clone()]);
        assert!(
            matches!(combined, Err(CombineError::Invalid { member }) if member == idx(1)),
            "combine names member 1"
        );
    }
    let after: Vec<usize> = members.values().map(Node::calls).collect();
    assert_eq!(
        after, before,
        "a threshold member never uses its one-of-one backend"
    );
}

#[tokio::test]
async fn a_share_is_issued_only_for_the_authorized_identity_and_key_version() {
    let db = fresh_db().await;
    let members = threshold_members(&db).await;
    let net = network_id();
    let member = &members[&2].service;

    let (version_one, ..) = threshold_request(KEY_PATH, 1);
    assert_refused(
        member
            .threshold_derive_shares(&net, KEY_PATH, 2, version_one.clone())
            .await,
        "another key version",
        unauthorized_identity,
    );
    assert_refused(
        member
            .threshold_derive_shares(&net, "apps/notes/k2", 1, version_one)
            .await,
        "another key path",
        unauthorized_identity,
    );
    assert_refused(
        member.threshold_public_material(&net, Epoch::new(1)).await,
        "another epoch",
        epoch_mismatch,
    );
}

#[tokio::test]
async fn key_state_revoke_and_re_create_refuse_a_threshold_row_under_both_flag_settings() {
    for threshold_v1 in [false, true] {
        let expected = if threshold_v1 { mismatch } else { disabled };
        let db = fresh_db().await;
        // A key created while the network was one-of-one, then the parent
        // row switched to threshold.
        let setup = node(&db, |service| service);
        network_row(&setup.service, &db, KeyBackendKind::LocalOneOfOne.as_str()).await;
        setup.service.create_key(&key_loc(), true).await.unwrap();
        set_key_backend(&db, KeyBackendKind::Threshold.as_str()).await;

        let node = node(&db, |service| service.with_threshold_v1(threshold_v1));
        let service = &node.service;
        let before = rows(&db).await;
        assert_eq!(before.keys.len(), 1);
        assert_refused(
            service.describe_key(&key_loc()).await,
            "describe_key",
            expected,
        );
        assert_refused(service.block_key(&key_loc()).await, "block_key", expected);
        assert_refused(
            service.unblock_key(&key_loc()).await,
            "unblock_key",
            expected,
        );
        assert_refused(
            service.revoke_network(&network_id()).await,
            "revoke_network",
            expected,
        );
        let create = || CreateNetworkRequest {
            name: NETWORK_NAME.to_string(),
            owner_did: owner_did(),
            threshold: Threshold::one_of_one(),
        };
        assert_refused(
            service.create_one_of_one_network(create()).await,
            "re-create",
            expected,
        );
        assert_eq!(rows(&db).await, before, "threshold_v1 = {threshold_v1}");

        // Half-created: no member row, which a create would otherwise repair.
        encryption_network_member::Entity::delete_many()
            .filter(encryption_network_member::Column::NetworkId.eq(network_id().to_string()))
            .exec(&db)
            .await
            .unwrap();
        let half_created = rows(&db).await;
        assert!(half_created.members.is_empty());
        assert_refused(
            service.create_one_of_one_network(create()).await,
            "repair",
            expected,
        );
        assert_eq!(
            rows(&db).await,
            half_created,
            "threshold_v1 = {threshold_v1}"
        );
        assert_eq!(node.calls(), 0, "threshold_v1 = {threshold_v1}");
    }
}
