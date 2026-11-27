//! The authorization set a threshold (t ≥ 2) network's members hold
//! (TC-2225, gate B §4).
//!
//! One set per network N, stored by the CID of each object's original bytes.
//! Four kinds:
//!
//! - `cert`: an owner-signed network certificate, checked with
//!   `verify_certificate` under the anchor `{owner of N, N}`, held when it
//!   names this node or succeeds a certificate the set holds;
//! - `activation`: the owner's activation of a stored certificate with every
//!   holder's readiness receipt (`ReadyQuorum::AllHolders`). A member creates
//!   N's network and member rows from the activated genesis;
//! - `revocation`: a UCAN or CACAO revocation with the revoked delegation, its
//!   proof chain and any control grant chain attached. Accepted on what it
//!   carries only, with no validity window checked, then inserted into the
//!   delegation graph under `/delegate`'s other admission rules;
//! - `key-state`: the owner's `key.state` or `network.revoke` statement. Key
//!   rows follow the highest `stateSeq`.
//!
//! Every verdict depends only on the object and the set's certificates, so
//! every member reaches the same one. A peer that sends an object the set
//! refuses has a fault recorded against it. Nothing is ever pruned.
//!
//! Wire encodings (`lp` is a u32 big-endian length then the bytes):
//!
//! - `cert`: `u8(1) || lp(certificate body) || lp(owner signature)`;
//! - `activation`: `u8(1) || certificate digest (32) || u16 count ||
//!   count × (u16 member index || lp(readiness signature)) ||
//!   lp(activation statement) || lp(owner signature)`;
//! - `revocation`: JSON `{"revocation": <header>, "delegations": [<header>…]}`;
//! - `key-state`: the statement's header encoding (a UCAN JWT or a CACAO).
//!
//! A statement carries one capability with one caveat object:
//!
//! - `tinycloud.encryption/key.state` on the key URN, caveat
//!   `{"version":1,"network":N,"owner":…,"action":"create"|"block"|"unblock",
//!   "stateSeq":…,"state":"active"|"blocked","keyVersion":…}`;
//! - `tinycloud.encryption/network.revoke` on N, caveat
//!   `{"version":1,"network":N,"owner":…}`.
//!
//! A `did:key` owner signs a UCAN addressed to itself with no proofs; its
//! `exp` is not read. A `did:pkh:eip155` owner signs a SIWE message whose only
//! resource is the ReCap, whose `uri` is N and which has no expiration.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use sea_orm::{
    sea_query::OnConflict, ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseTransaction,
    DbErr, EntityTrait, QueryFilter, QueryOrder, QuerySelect, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest, Keccak256};
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation, TinyCloudRevocation},
    cacaos::siwe::{encode_eip55, Message},
    identity::did_principal_matches,
    siwe_recap::{Capability as Recap, RESOURCE_PREFIX},
    ucan_capabilities_object::{Ability, Caveats},
};
use tinycloud_threshold::{
    verify_activation, verify_certificate, verify_successor, CertificateBody, Did,
    DidSignatureVerifier, MemberIndex, NetworkUrn, ReadinessReceipt, ReadyQuorum, SignatureError,
    SignedCertificate, SignedStatement, TrustAnchor, VerifiedCertificate,
};

use crate::{
    db_pool::RecoveringConnection,
    encryption::ColumnEncryption,
    events::{Delegation, Revocation},
    hash::{hash, Hash},
    keys::{public_key_to_did_key, Keypair},
    models::{
        delegation, encryption_network, encryption_network_member, revocation, threshold_fault,
        threshold_key_row, threshold_network_revocation, threshold_set_object,
    },
    relationships::parent_delegations,
    util::{Capability, DelegationInfo},
};

use super::{
    key_id::{self, EncryptionResource},
    keys::threshold_refuses_path,
    network_id::NetworkId,
    protocol::NETWORK_REVOKE_ACTION,
    service::{now_rfc3339, EncryptionServiceError},
    types::{KeyBackendKind, NetworkState},
};

/// Domain of the member's signed acknowledgement of a pushed object.
pub const ACK_DOMAIN: &[u8] = b"tc-threshold-authset-ack-v1";
/// The owner's key-state ability.
pub const KEY_STATE_ACTION: &str = "tinycloud.encryption/key.state";
/// Largest `stateSeq` and `keyVersion` a statement may carry.
pub const MAX_STATE_SEQ: u64 = 1 << 32;
/// Largest object the set takes.
pub const MAX_OBJECT_BYTES: usize = 256 * 1024;
/// Longest client nonce an acknowledgement echoes.
pub const MAX_NONCE_BYTES: usize = 128;
/// Largest number of delegations a revocation may attach.
const MAX_ATTACHED: usize = revocation::MAX_CHAIN_TRAVERSAL_NODES;
/// The maximum invocation lifetime: the authority window's span when a
/// revocation carries only one end of it.
const MAX_INVOCATION_TTL_SECS: i64 = 3600;
const RAW_CODEC: u64 = 0x55;
const REVOKE_ABILITY: &str = "tinycloud.delegation/revoke";
/// `alg` of a threshold network row: BLS12-381 threshold identity-based
/// keys (`tinycloud-threshold`). Its public key is the master public key.
const THRESHOLD_ALG: &str = "tc-threshold-bls12-381/v1";
/// `role` of a threshold network's member rows.
const MEMBER_ROLE: &str = "member";

/// What an object of the set is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    Cert,
    Activation,
    Revocation,
    KeyState,
}

impl ObjectKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cert => "cert",
            Self::Activation => "activation",
            Self::Revocation => "revocation",
            Self::KeyState => "key-state",
        }
    }

    pub fn parse(kind: &str) -> Option<Self> {
        Some(match kind {
            "cert" => Self::Cert,
            "activation" => Self::Activation,
            "revocation" => Self::Revocation,
            "key-state" => Self::KeyState,
            _ => return None,
        })
    }
}

/// Who handed the node an object. A refusal of a peer's object is that
/// peer's fault; a client's is not recorded.
#[derive(Clone, Copy, Debug)]
pub enum Source<'a> {
    Client,
    Peer(&'a str),
}

/// A member's state for one key after a statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyView {
    pub path: String,
    pub state_seq: u64,
    /// `active`, `blocked`, or `revoked` once the network is revoked.
    pub state: String,
    pub key_version: u64,
}

/// An object the set holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub cid: String,
    /// False when the set already held these bytes.
    pub new: bool,
    /// For a `key.state` statement, the key's resulting state.
    pub key: Option<KeyView>,
}

/// Why an object is not in the set.
#[derive(Debug, thiserror::Error)]
pub enum AcceptError {
    /// The object is invalid for N; every member refuses it.
    #[error("threshold_object_refused: {0}")]
    Refused(&'static str),
    /// The object may be valid, but the set lacks what it is checked against.
    #[error("threshold_object_unavailable: {0}")]
    Unavailable(&'static str),
    #[error(transparent)]
    Db(#[from] DbErr),
}

fn refused(reason: &'static str) -> AcceptError {
    AcceptError::Refused(reason)
}

/// The member's signed acknowledgement of a held object.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ack {
    pub network: String,
    pub nonce: String,
    pub cid: String,
    pub outcome: &'static str,
    pub key: Option<KeyView>,
    pub node: String,
    /// base64url (no padding) Ed25519 signature over [`ack_preimage`].
    pub signature: String,
}

/// The bytes a member signs to acknowledge `cid`:
///
/// `ACK_DOMAIN || lp(N) || lp(nonce) || lp(cid) || lp(outcome) || key`, where
/// `key` is `u8(0)`, or `u8(1) || lp(path) || u64 stateSeq || lp(state) ||
/// u64 keyVersion` (big-endian) for a `key.state` statement.
pub fn ack_preimage(
    network: &str,
    nonce: &str,
    cid: &str,
    outcome: &str,
    key: Option<&KeyView>,
) -> Vec<u8> {
    let mut out = ACK_DOMAIN.to_vec();
    for part in [network, nonce, cid, outcome] {
        put_lp(&mut out, part.as_bytes());
    }
    match key {
        None => out.push(0),
        Some(key) => {
            out.push(1);
            put_lp(&mut out, key.path.as_bytes());
            out.extend_from_slice(&key.state_seq.to_be_bytes());
            put_lp(&mut out, key.state.as_bytes());
            out.extend_from_slice(&key.key_version.to_be_bytes());
        }
    }
    out
}

fn put_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// The CID (raw codec) an object is stored under.
pub fn object_cid(bytes: &[u8]) -> String {
    hash(bytes).to_cid(RAW_CODEC).to_string()
}

/// A client nonce an acknowledgement echoes: 1 to 128 printable ASCII
/// characters.
pub fn check_nonce(nonce: &str) -> Result<(), String> {
    if nonce.is_empty()
        || nonce.len() > MAX_NONCE_BYTES
        || !nonce.bytes().all(|b| b.is_ascii_graphic())
    {
        return Err("nonce must be 1 to 128 printable ASCII characters".to_string());
    }
    Ok(())
}

// ------------------------------------------------------------------ network

/// Whether `net` is a threshold network: the threshold backend with t ≥ 2.
pub(crate) fn is_threshold(net: &encryption_network::Model) -> bool {
    net.key_backend == KeyBackendKind::Threshold.as_str() && net.threshold_t >= 2
}

/// B3-1: a threshold network takes the owner's signed statements only, so a
/// node-bound network-admin or key-admin credential is refused. A network
/// this node has no row for is unaffected.
pub(crate) async fn refuse_node_bound<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
) -> Result<(), EncryptionServiceError> {
    let net = encryption_network::Entity::find_by_id(network.to_string())
        .one(db)
        .await?;
    if net.as_ref().is_some_and(is_threshold) {
        return Err(EncryptionServiceError::OwnerOnly(
            "a threshold network takes the owner's signed statements, not node-bound credentials"
                .to_string(),
        ));
    }
    Ok(())
}

// ----------------------------------------------------------------- verifier

/// The DIDs a certificate, readiness receipt or activation is signed by:
/// Ed25519 `did:key` (strict, no small-order key) and `did:pkh:eip155`
/// (EIP-191 `personal_sign` of the message), each also on the node's offline
/// DID allow-list (`check_verifiable`). Every other DID is refused.
pub struct NodeDidVerifier;

impl DidSignatureVerifier for NodeDidVerifier {
    fn verify(&self, signer: &Did, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
        let did = signer.as_str();
        tinycloud_auth::ssi::dids::DID::new(did.as_bytes())
            .ok()
            .and_then(|parsed| crate::did_resolution::check_verifiable(parsed).ok())
            .ok_or(SignatureError::Invalid)?;
        if did.starts_with("did:key:") {
            tinycloud_auth::share_email_evidence::verify_detached_ed25519(did, message, signature)
                .map_err(|_| SignatureError::Invalid)
        } else {
            verify_eip191(did, message, signature)
        }
    }
}

fn verify_eip191(did: &str, message: &[u8], signature: &[u8]) -> Result<(), SignatureError> {
    fn invalid<E>(_: E) -> SignatureError {
        SignatureError::Invalid
    }
    let pkh = tinycloud_auth::identity::parse_pkh_did(did)
        .map_err(invalid)?
        .ok_or(SignatureError::Invalid)?;
    let [rs @ .., v] = signature else {
        return Err(SignatureError::Invalid);
    };
    if rs.len() != 64 {
        return Err(SignatureError::Invalid);
    }
    let recovery = match v {
        27 | 28 => RecoveryId::try_from(v - 27),
        0 | 1 => RecoveryId::try_from(*v),
        _ => return Err(SignatureError::Invalid),
    }
    .map_err(invalid)?;
    let mut preimage = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    preimage.extend_from_slice(message);
    let digest = Keccak256::digest(preimage);
    let signature = Signature::from_slice(rs).map_err(invalid)?;
    let key = VerifyingKey::recover_from_prehash(&digest, &signature, recovery).map_err(invalid)?;
    let public = key.to_encoded_point(false);
    let address = Keccak256::digest(&public.as_bytes()[1..]);
    let expected = pkh
        .address
        .strip_prefix("0x")
        .and_then(|value| hex::decode(value).ok())
        .ok_or(SignatureError::Invalid)?;
    if address[12..] != expected[..] {
        return Err(SignatureError::Invalid);
    }
    Ok(())
}

// ------------------------------------------------------------------- codecs

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.0.len() < n {
            return None;
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Some(head)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }
    fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }
    fn lp(&mut self) -> Option<&'a [u8]> {
        let n = self.take(4)?;
        let n = u32::from_be_bytes([n[0], n[1], n[2], n[3]]) as usize;
        self.take(n)
    }
    fn done(&self) -> bool {
        self.0.is_empty()
    }
}

/// Decodes a `cert` object.
pub fn decode_cert(bytes: &[u8]) -> Option<SignedCertificate> {
    let mut r = Reader(bytes);
    if r.u8()? != 1 {
        return None;
    }
    let body = CertificateBody::decode(r.lp()?).ok()?;
    let owner_signature = r.lp()?.to_vec();
    r.done().then_some(SignedCertificate {
        body,
        owner_signature,
    })
}

/// Encodes a `cert` object.
pub fn encode_cert(signed: &SignedCertificate) -> Vec<u8> {
    let mut out = vec![1];
    put_lp(&mut out, &signed.body.encode());
    put_lp(&mut out, &signed.owner_signature);
    out
}

/// A decoded `activation` object.
pub struct ActivationObject {
    pub certificate: [u8; 32],
    pub receipts: Vec<ReadinessReceipt>,
    pub activation: SignedStatement,
}

/// Decodes an `activation` object.
pub fn decode_activation(bytes: &[u8]) -> Option<ActivationObject> {
    let mut r = Reader(bytes);
    if r.u8()? != 1 {
        return None;
    }
    let certificate: [u8; 32] = r.take(32)?.try_into().ok()?;
    let count = r.u16()?;
    if count > 16 {
        return None;
    }
    let mut receipts = Vec::with_capacity(usize::from(count));
    for _ in 0..count {
        let index = MemberIndex::new(r.u16()?).ok()?;
        receipts.push(ReadinessReceipt {
            index,
            signature: r.lp()?.to_vec(),
        });
    }
    let bytes = r.lp()?.to_vec();
    let signature = r.lp()?.to_vec();
    r.done().then_some(ActivationObject {
        certificate,
        receipts,
        activation: SignedStatement { bytes, signature },
    })
}

/// Encodes an `activation` object.
pub fn encode_activation(object: &ActivationObject) -> Vec<u8> {
    let mut out = vec![1];
    out.extend_from_slice(&object.certificate);
    out.extend_from_slice(&(object.receipts.len() as u16).to_be_bytes());
    for receipt in &object.receipts {
        out.extend_from_slice(&receipt.index.get().to_be_bytes());
        put_lp(&mut out, &receipt.signature);
    }
    put_lp(&mut out, &object.activation.bytes);
    put_lp(&mut out, &object.activation.signature);
    out
}

/// A `revocation` object.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationObject {
    /// The revocation's header encoding.
    pub revocation: String,
    /// Header encodings of the revoked delegation, its proof chain and any
    /// control grant chain.
    pub delegations: Vec<String>,
}

// --------------------------------------------------------------- statements

/// A key's state as a statement sets it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatementState {
    Active,
    Blocked,
}

impl StatementState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Blocked => "blocked",
        }
    }
}

/// The owner's approval label of a `key.state` statement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StatementAction {
    Create,
    Block,
    Unblock,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct KeyStateCaveat {
    version: u8,
    network: String,
    owner: String,
    action: StatementAction,
    state_seq: u64,
    state: StatementState,
    key_version: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NetworkRevokeCaveat {
    version: u8,
    network: String,
    owner: String,
}

/// What a verified statement changes.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Change {
    Key {
        path: String,
        state_seq: u64,
        state: StatementState,
        key_version: u64,
    },
    NetworkRevoke,
}

/// The one capability a statement carries: resource, ability and its caveat
/// list as JSON.
fn single_capability<'a, U: ToString + 'a, T: Serialize + 'a>(
    caps: impl IntoIterator<Item = (&'a U, &'a BTreeMap<Ability, Caveats<T>>)>,
) -> Option<(String, String, Value)> {
    let mut caps = caps.into_iter();
    let (resource, abilities) = caps.next()?;
    if caps.next().is_some() || abilities.len() != 1 {
        return None;
    }
    let (ability, caveats) = abilities.iter().next()?;
    let caveats = serde_json::to_value(caveats.as_ref()).ok()?;
    Some((resource.to_string(), ability.to_string(), caveats))
}

/// Reads the change a statement's capability names, for network `network`.
fn statement_change(
    network: &NetworkId,
    resource: &str,
    ability: &str,
    caveats: Value,
) -> Result<Change, AcceptError> {
    let Value::Array(mut caveats) = caveats else {
        return Err(refused("statement_malformed"));
    };
    let (Some(caveat), true) = (caveats.pop(), caveats.is_empty()) else {
        return Err(refused("statement_malformed"));
    };
    let owner = network.owner_did();
    let network_urn = network.to_string();
    match ability {
        KEY_STATE_ACTION => {
            let caveat: KeyStateCaveat =
                serde_json::from_value(caveat).map_err(|_| refused("statement_malformed"))?;
            let EncryptionResource::Key(location) =
                key_id::parse(resource).map_err(|_| refused("statement_resource"))?
            else {
                return Err(refused("statement_resource"));
            };
            let resource_network = NetworkId::new(location.owner_did(), location.network())
                .map_err(|_| refused("statement_resource"))?;
            if resource_network != *network
                || EncryptionResource::Key(location.clone()).to_string() != resource
            {
                return Err(refused("statement_resource"));
            }
            if caveat.version != 1 || caveat.network != network_urn || caveat.owner != owner {
                return Err(refused("statement_network"));
            }
            if !(1..=MAX_STATE_SEQ).contains(&caveat.state_seq)
                || !(1..=MAX_STATE_SEQ).contains(&caveat.key_version)
            {
                return Err(refused("statement_sequence_range"));
            }
            let consistent = matches!(
                (caveat.action, caveat.state),
                (StatementAction::Create, StatementState::Active)
                    | (StatementAction::Block, StatementState::Blocked)
                    | (StatementAction::Unblock, StatementState::Active)
            );
            if !consistent {
                return Err(refused("statement_action_state"));
            }
            Ok(Change::Key {
                path: location.path().to_string(),
                state_seq: caveat.state_seq,
                state: caveat.state,
                key_version: caveat.key_version,
            })
        }
        NETWORK_REVOKE_ACTION => {
            let caveat: NetworkRevokeCaveat =
                serde_json::from_value(caveat).map_err(|_| refused("statement_malformed"))?;
            if resource != network_urn
                || caveat.version != 1
                || caveat.network != network_urn
                || caveat.owner != owner
            {
                return Err(refused("statement_network"));
            }
            Ok(Change::NetworkRevoke)
        }
        _ => Err(refused("statement_ability")),
    }
}

/// Verifies an owner statement for `network`: the encoding the owner's DID
/// method takes, the signature through the node's DID verifier, and the
/// change it names. No time is checked.
async fn verify_statement(network: &NetworkId, bytes: &[u8]) -> Result<Change, AcceptError> {
    let header = std::str::from_utf8(bytes).map_err(|_| refused("statement_malformed"))?;
    let (statement, _) =
        TinyCloudDelegation::decode(header).map_err(|_| refused("statement_malformed"))?;
    let owner = network.owner_did();
    match statement {
        TinyCloudDelegation::Ucan(ucan) if owner.starts_with("did:key:") => {
            crate::did_resolution::verify_ucan_signature(&ucan)
                .await
                .map_err(|_| refused("statement_signature"))?;
            let payload = ucan.payload();
            let issuer = payload.issuer.to_string();
            let issuer = issuer.split('#').next().unwrap_or_default();
            if issuer != owner || payload.audience.as_str() != owner {
                return Err(refused("statement_signer"));
            }
            if !payload.proof.is_empty() {
                return Err(refused("statement_malformed"));
            }
            let (resource, ability, caveats) = single_capability(payload.attenuation.abilities())
                .ok_or_else(|| refused("statement_malformed"))?;
            statement_change(network, &resource, &ability, caveats)
        }
        TinyCloudDelegation::Cacao(cacao) if owner.starts_with("did:pkh:eip155:") => {
            cacao
                .verify()
                .await
                .map_err(|_| refused("statement_signature"))?;
            let message: Message = cacao
                .payload()
                .clone()
                .try_into()
                .map_err(|_| refused("statement_signer"))?;
            let signer = format!(
                "did:pkh:eip155:{}:0x{}",
                message.chain_id,
                encode_eip55(&message.address)
            );
            if !did_principal_matches(&signer, owner) {
                return Err(refused("statement_signer"));
            }
            if message.uri.as_str() != network.to_string() || message.expiration_time.is_some() {
                return Err(refused("statement_binding"));
            }
            let [resource] = message.resources.as_slice() else {
                return Err(refused("statement_malformed"));
            };
            if !resource.as_str().starts_with(RESOURCE_PREFIX) {
                return Err(refused("statement_malformed"));
            }
            let recap = Recap::<Value>::extract_and_verify(&message)
                .map_err(|_| refused("statement_malformed"))?
                .ok_or_else(|| refused("statement_malformed"))?;
            if !recap.proof().is_empty() {
                return Err(refused("statement_malformed"));
            }
            let (resource, ability, caveats) = single_capability(recap.abilities())
                .ok_or_else(|| refused("statement_malformed"))?;
            statement_change(network, &resource, &ability, caveats)
        }
        _ => Err(refused("statement_encoding")),
    }
}

// --------------------------------------------------------------- revocation

/// The authority window of a revocation (gate B §4.2 step 3), from what it
/// carries: [`nbf`, else `iat`, else `exp` − 3600 s; `exp`, else start +
/// 3600 s]. None when it carries neither a start nor an end. Unix seconds.
pub fn authority_window(
    nbf: Option<i64>,
    iat: Option<i64>,
    exp: Option<i64>,
) -> Option<(i64, i64)> {
    let start = nbf
        .or(iat)
        .or_else(|| exp.map(|exp| exp.saturating_sub(MAX_INVOCATION_TTL_SECS)))?;
    let end = exp.unwrap_or_else(|| start.saturating_add(MAX_INVOCATION_TTL_SECS));
    Some((start, end))
}

/// Whether a grant valid from `not_before` until before `expiry` is valid at
/// some instant of `window`.
fn intersects(
    window: (i64, i64),
    not_before: Option<OffsetDateTime>,
    expiry: Option<OffsetDateTime>,
) -> bool {
    let (start, end) = window;
    start <= end
        && not_before.is_none_or(|nbf| nbf.unix_timestamp() <= end)
        && expiry.is_none_or(|exp| start < exp.unix_timestamp())
}

fn revocation_window(revocation: &TinyCloudRevocation) -> Option<(i64, i64)> {
    match revocation {
        TinyCloudRevocation::Ucan(ucan) => {
            let payload = ucan.payload();
            authority_window(
                payload.not_before.map(|t| t.as_seconds() as i64),
                None,
                Some(payload.expiration.as_seconds() as i64),
            )
        }
        TinyCloudRevocation::Cacao(cacao) => {
            let seconds = |t: &tinycloud_auth::cacaos::siwe::TimeStamp| {
                let instant: &OffsetDateTime = t.as_ref();
                instant.unix_timestamp()
            };
            let payload = cacao.payload();
            authority_window(
                payload.nbf.as_ref().map(seconds),
                Some(seconds(&payload.iat)),
                payload.exp.as_ref().map(seconds),
            )
        }
    }
}

/// The network an encryption resource names.
fn network_of_resource(resource: &str) -> Option<NetworkId> {
    match key_id::parse(resource).ok()? {
        EncryptionResource::Network(network) => Some(network),
        EncryptionResource::Key(location) | EncryptionResource::KeyPrefix(location) => {
            NetworkId::new(location.owner_did(), location.network()).ok()
        }
    }
}

/// §4.1: a delegation is in N's scope when one of its capabilities is a
/// `tinycloud.encryption/*` ability on N, a key under N or a key prefix
/// under N.
fn in_scope(network: &NetworkId, delegation: &DelegationInfo) -> bool {
    delegation.capabilities.iter().any(|cap| {
        cap.ability.to_string().starts_with("tinycloud.encryption/")
            && network_of_resource(&cap.resource.to_string()).as_ref() == Some(network)
    })
}

fn is_root_authority(cap: &Capability, delegator: &str) -> bool {
    cap.resource.owned_by(delegator)
}

/// Whether `parent` grants what `child` claims: resource, ability, and
/// caveats. Selector caveats follow `/delegate`'s containment rule, which
/// also refuses a malformed selector; other caveats must equal the parent's
/// or sit under a parent that has none.
fn covers(parent: &Capability, child: &Capability) -> bool {
    child.resource.extends(&parent.resource)
        && crate::policy_capability::ability_matches(
            &parent.ability.to_string(),
            &child.ability.to_string(),
        )
        && match crate::policy_capability::selector_caveats_contain(
            &parent.caveats.0,
            &child.caveats.0,
        ) {
            Some(contained) => contained,
            None => parent.caveats.0.is_empty() || parent.caveats == child.caveats,
        }
}

struct Attached {
    info: DelegationInfo,
    bytes: Vec<u8>,
}

/// The ids of `root` and its proof ancestors, parents before children, all
/// attached and each attenuated from its parents. `extra_root_cap` admits a
/// parentless capability that is not root authority (a revoke grant checked
/// by the caller).
fn checked_chain(
    root: Hash,
    attached: &HashMap<Hash, Attached>,
    extra_root_cap: &dyn Fn(Hash, &Capability) -> bool,
) -> Result<Vec<Hash>, AcceptError> {
    let mut order = Vec::new();
    let mut seen = BTreeSet::new();
    let mut stack = vec![(root, false)];
    while let Some((id, expanded)) = stack.pop() {
        if expanded {
            order.push(id);
            continue;
        }
        if !seen.insert(id) {
            continue;
        }
        let item = attached
            .get(&id)
            .ok_or_else(|| refused("chain_incomplete"))?;
        let info = &item.info;
        let mut parents = Vec::new();
        for parent in &info.parents {
            let parent_id = Hash::from(*parent);
            let parent = attached
                .get(&parent_id)
                .ok_or_else(|| refused("chain_incomplete"))?;
            if !did_principal_matches(&parent.info.delegate, &info.delegator) {
                return Err(refused("chain_attenuation"));
            }
            parents.push(&parent.info);
        }
        for cap in &info.capabilities {
            let held = is_root_authority(cap, &info.delegator)
                || (parents.is_empty() && extra_root_cap(id, cap))
                || parents
                    .iter()
                    .any(|parent| parent.capabilities.iter().any(|p| covers(p, cap)));
            if !held {
                return Err(refused("chain_attenuation"));
            }
        }
        stack.push((id, true));
        for parent in &info.parents {
            stack.push((Hash::from(*parent), false));
        }
    }
    Ok(order)
}

/// The revoke scopes of a control grant `grant` that cover every capability
/// of `target` (exactly `urn:cid:<target>`, or a network the grantor owns
/// that every target capability is in).
fn grant_covers_target(grant: &DelegationInfo, target_id: Hash, target: &DelegationInfo) -> bool {
    grant.capabilities.iter().any(|cap| {
        if cap.ability.to_string() != REVOKE_ABILITY {
            return false;
        }
        let resource = cap.resource.to_string();
        if let Some(cid) = resource.strip_prefix("urn:cid:") {
            return cid
                .parse::<tinycloud_auth::authorization::Cid>()
                .is_ok_and(|cid| Hash::from(cid) == target_id);
        }
        resource.parse::<NetworkId>().is_ok_and(|scope| {
            did_principal_matches(scope.owner_did(), &grant.delegator)
                && !target.capabilities.is_empty()
                && target.capabilities.iter().all(|target_cap| {
                    network_of_resource(&target_cap.resource.to_string()).as_ref() == Some(&scope)
                })
        })
    })
}

/// A revocation the set accepts: what to insert, in order.
struct RevocationPlan {
    revocation: Revocation,
    target: Hash,
    /// Every delegation to insert, parents before children.
    chain: Vec<Delegation>,
}

/// Gate B §4.2 steps 1-4 for `bytes`, with no database read.
async fn verify_revocation(
    network: &NetworkId,
    bytes: &[u8],
) -> Result<RevocationPlan, AcceptError> {
    let object: RevocationObject =
        serde_json::from_slice(bytes).map_err(|_| refused("revocation_malformed"))?;
    if object.delegations.is_empty() || object.delegations.len() > MAX_ATTACHED {
        return Err(refused("revocation_malformed"));
    }
    let revocation = Revocation::from_header_ser::<TinyCloudRevocation>(&object.revocation)
        .map_err(|_| refused("revocation_malformed"))?;
    revocation::check_signature(&revocation.0.revocation)
        .await
        .map_err(|_| refused("revocation_signature"))?;

    // Step 1: every attached delegation's signature, no time window.
    let mut attached = HashMap::new();
    for header in &object.delegations {
        let parsed = Delegation::from_header_ser::<TinyCloudDelegation>(header)
            .map_err(|_| refused("delegation_malformed"))?;
        delegation::check_signature(&parsed.0.delegation)
            .await
            .map_err(|_| refused("delegation_signature"))?;
        let id = parsed.content_hash();
        let bytes = parsed.serialized_bytes().to_vec();
        if attached
            .insert(
                id,
                Attached {
                    info: parsed.0,
                    bytes,
                },
            )
            .is_some()
        {
            return Err(refused("revocation_malformed"));
        }
    }
    let target = Hash::from(revocation.0.revoked);
    let target_info = &attached
        .get(&target)
        .ok_or_else(|| refused("revoked_delegation_missing"))?
        .info;
    // §4.1.
    if !in_scope(network, target_info) {
        return Err(refused("out_of_scope"));
    }
    let mut order = checked_chain(target, &attached, &|_, _| false)?;

    // Step 2: the revoker.
    let revoker = &revocation.0.revoker;
    let direct = did_principal_matches(&target_info.delegator, revoker)
        || did_principal_matches(network.owner_did(), revoker);
    if !direct {
        // (c): one control grant from the target's delegator or the owner,
        // held by the revoker, in force during the authority window.
        let [proof] = revocation.0.parents.as_slice() else {
            return Err(refused("revoker_unauthorized"));
        };
        let grant_id = Hash::from(*proof);
        let grant = &attached
            .get(&grant_id)
            .ok_or_else(|| refused("revoker_unauthorized"))?
            .info;
        let grantor_may = did_principal_matches(&grant.delegator, &target_info.delegator)
            || did_principal_matches(&grant.delegator, network.owner_did())
            || target_info
                .capabilities
                .iter()
                .any(|cap| cap.resource.owned_by(&grant.delegator));
        if !grantor_may
            || !did_principal_matches(&grant.delegate, revoker)
            || !grant_covers_target(grant, target, target_info)
        {
            return Err(refused("revoker_unauthorized"));
        }
        let window = revocation_window(&revocation.0.revocation)
            .ok_or_else(|| refused("revoker_unauthorized"))?;
        if !intersects(window, grant.not_before, grant.expiry) {
            return Err(refused("control_grant_window"));
        }
        let exact_cid = |id: Hash, cap: &Capability| {
            id == grant_id
                && cap.ability.to_string() == REVOKE_ABILITY
                && cap
                    .resource
                    .to_string()
                    .strip_prefix("urn:cid:")
                    .is_some_and(|cid| {
                        cid.parse::<tinycloud_auth::authorization::Cid>()
                            .is_ok_and(|cid| Hash::from(cid) == target)
                    })
        };
        for id in checked_chain(grant_id, &attached, &exact_cid)? {
            if !order.contains(&id) {
                order.push(id);
            }
        }
    }
    // Every attached delegation is in one of the two chains.
    if order.len() != attached.len() {
        return Err(refused("revocation_malformed"));
    }
    let chain = order
        .into_iter()
        .filter_map(|id| attached.remove(&id))
        .map(|item| crate::events::SerializedEvent(item.info, item.bytes))
        .collect();
    Ok(RevocationPlan {
        revocation,
        target,
        chain,
    })
}

// --------------------------------------------------------------------- set

/// A node's threshold authorization sets.
#[derive(Clone)]
pub struct ThresholdSet {
    db: RecoveringConnection,
    node_did: String,
    node_keypair: Keypair,
    encryption: Option<ColumnEncryption>,
    delegated_sql_caveats: bool,
    named_keys: bool,
}

impl ThresholdSet {
    /// `encryption` is the column key the delegation graph's signed bytes are
    /// stored under.
    pub fn new(
        db: impl Into<RecoveringConnection>,
        node_keypair: Keypair,
        encryption: Option<ColumnEncryption>,
    ) -> Self {
        Self {
            db: db.into(),
            node_did: public_key_to_did_key(node_keypair.public()),
            node_keypair,
            encryption,
            delegated_sql_caveats: false,
            named_keys: false,
        }
    }

    /// The node's `/delegate` settings, which a revocation's attached
    /// delegations are admitted under: delegated SQL caveats (TC-1791) and
    /// named keys. Both are off by default, as on the node.
    pub fn with_delegation_rules(mut self, delegated_sql_caveats: bool, named_keys: bool) -> Self {
        self.delegated_sql_caveats = delegated_sql_caveats;
        self.named_keys = named_keys;
        self
    }

    pub fn node_did(&self) -> &str {
        &self.node_did
    }

    /// Checks `bytes` as an object of kind `kind` for `network` and, when
    /// valid, adds it to the set and applies it. A refusal of a peer's object
    /// is recorded as that peer's fault.
    pub async fn accept(
        &self,
        network: &NetworkId,
        kind: ObjectKind,
        bytes: &[u8],
        source: Source<'_>,
    ) -> Result<Accepted, AcceptError> {
        let cid = object_cid(bytes);
        let result = self.accept_inner(network, kind, bytes, &cid).await;
        if let (Err(AcceptError::Refused(reason)), Source::Peer(peer)) = (&result, source) {
            record_fault(&self.db, network, peer, &cid, reason).await?;
        }
        result
    }

    async fn accept_inner(
        &self,
        network: &NetworkId,
        kind: ObjectKind,
        bytes: &[u8],
        cid: &str,
    ) -> Result<Accepted, AcceptError> {
        if bytes.is_empty() || bytes.len() > MAX_OBJECT_BYTES {
            return Err(refused("object_size"));
        }
        if let Some(held) = self.held(network, cid).await? {
            if held.kind != kind.as_str() {
                return Err(refused("object_kind"));
            }
            let key = match kind {
                ObjectKind::KeyState if !held.subject.is_empty() => {
                    self.key_view(&self.db, network, &held.subject).await?
                }
                _ => None,
            };
            return Ok(Accepted {
                cid: cid.to_string(),
                new: false,
                key,
            });
        }
        match kind {
            ObjectKind::Cert => self.accept_cert(network, bytes, cid).await,
            ObjectKind::Activation => self.accept_activation(network, bytes, cid).await,
            ObjectKind::Revocation => self.accept_revocation(network, bytes, cid).await,
            ObjectKind::KeyState => self.accept_key_state(network, bytes, cid).await,
        }
    }

    async fn held(
        &self,
        network: &NetworkId,
        cid: &str,
    ) -> Result<Option<threshold_set_object::Model>, DbErr> {
        threshold_set_object::Entity::find_by_id((network.to_string(), cid.to_string()))
            .one(&self.db)
            .await
    }

    async fn accept_cert(
        &self,
        network: &NetworkId,
        bytes: &[u8],
        cid: &str,
    ) -> Result<Accepted, AcceptError> {
        let signed = decode_cert(bytes).ok_or_else(|| refused("certificate_malformed"))?;
        let verified = verify_certificate(&anchor(network)?, &signed, &NodeDidVerifier)
            .map_err(|_| refused("certificate_invalid"))?;
        // A node holds only chains it serves: a certificate naming it, or a
        // successor of a certificate it holds, which may leave it out.
        let names_this_node = verified
            .body()
            .members()
            .iter()
            .any(|member| member.node.as_str() == self.node_did);
        let continues_held = match verified.body().previous() {
            Some(previous) => find_object(
                &self.db,
                network,
                ObjectKind::Cert,
                &hex::encode(previous.as_bytes()),
            )
            .await?
            .is_some(),
            None => false,
        };
        if !names_this_node && !continues_held {
            return Err(AcceptError::Unavailable("not_a_member"));
        }
        let subject = hex::encode(verified.digest().as_bytes());
        let tx = self.db.begin().await?;
        let new = store(&tx, network, cid, ObjectKind::Cert, &subject, bytes).await?;
        tx.commit().await?;
        Ok(accepted(cid, new, None))
    }

    async fn accept_activation(
        &self,
        network: &NetworkId,
        bytes: &[u8],
        cid: &str,
    ) -> Result<Accepted, AcceptError> {
        let object = decode_activation(bytes).ok_or_else(|| refused("activation_malformed"))?;
        let subject = hex::encode(object.certificate);
        let certificate = self
            .stored_certificate(&self.db, network, &subject)
            .await?
            .ok_or(AcceptError::Unavailable("certificate_missing"))?;
        verify_activation(
            &certificate,
            &object.receipts,
            ReadyQuorum::AllHolders,
            &object.activation,
            &NodeDidVerifier,
        )
        .map_err(|_| refused("activation_invalid"))?;
        let tx = self.db.begin().await?;
        let names_this_node = certificate
            .body()
            .members()
            .iter()
            .any(|member| member.node.as_str() == self.node_did);
        if certificate.body().previous().is_none() && names_this_node {
            if let Err(error) = create_network(&tx, network, &certificate).await {
                tx.rollback().await?;
                return Err(error);
            }
        }
        let new = store(&tx, network, cid, ObjectKind::Activation, &subject, bytes).await?;
        tx.commit().await?;
        Ok(accepted(cid, new, None))
    }

    async fn accept_key_state(
        &self,
        network: &NetworkId,
        bytes: &[u8],
        cid: &str,
    ) -> Result<Accepted, AcceptError> {
        let change = verify_statement(network, bytes).await?;
        if let Change::Key { path, .. } = &change {
            // D3: no deletable key on a threshold network.
            if threshold_refuses_path(path) {
                return Err(refused("deletable_key_path"));
            }
        }
        self.require_member(network).await?;
        let tx = self.db.begin().await?;
        let (new, key) = match &change {
            Change::NetworkRevoke => {
                let new = store(&tx, network, cid, ObjectKind::KeyState, "", bytes).await?;
                threshold_network_revocation::Entity::insert(
                    threshold_network_revocation::ActiveModel {
                        network_id: Set(network.to_string()),
                        statement_cid: Set(cid.to_string()),
                        recorded_at: Set(now_rfc3339()),
                    },
                )
                .on_conflict(
                    OnConflict::column(threshold_network_revocation::Column::NetworkId)
                        .do_nothing()
                        .to_owned(),
                )
                .exec_without_returning(&tx)
                .await?;
                (new, None)
            }
            Change::Key {
                path,
                state_seq,
                state,
                key_version,
            } => {
                let new = store(&tx, network, cid, ObjectKind::KeyState, path, bytes).await?;
                let conflict =
                    merge(&tx, network, path, cid, *state_seq, *state, *key_version).await?;
                if conflict {
                    record_fault(&tx, network, network.owner_did(), cid, "key_state_conflict")
                        .await?;
                }
                (new, self.key_view(&tx, network, path).await?)
            }
        };
        tx.commit().await?;
        Ok(accepted(cid, new, key))
    }

    async fn accept_revocation(
        &self,
        network: &NetworkId,
        bytes: &[u8],
        cid: &str,
    ) -> Result<Accepted, AcceptError> {
        let plan = verify_revocation(network, bytes).await?;
        self.require_member(network).await?;
        let subject = plan.target.to_cid(RAW_CODEC).to_string();
        let tx = self.db.begin().await?;
        // Step 5: the chain goes in under /delegate's admission rules except
        // the time windows and revoked ancestors (`process_carried`), then
        // the revocation row. A chain member a space purge already erased as
        // revoked leaves the graph as it is: its descendants are refused.
        if let Err(error) = self.insert_revocation(&tx, plan).await {
            tx.rollback().await?;
            return match error {
                delegation::Error::InvalidDelegation(delegation::DelegationError::Revoked(_)) => {
                    let tx = self.db.begin().await?;
                    let new =
                        store(&tx, network, cid, ObjectKind::Revocation, &subject, bytes).await?;
                    tx.commit().await?;
                    Ok(accepted(cid, new, None))
                }
                delegation::Error::Db(error) => Err(error.into()),
                delegation::Error::InvalidDelegation(_) => Err(refused("delegation_unstorable")),
            };
        }
        let new = store(&tx, network, cid, ObjectKind::Revocation, &subject, bytes).await?;
        tx.commit().await?;
        Ok(accepted(cid, new, None))
    }

    async fn insert_revocation(
        &self,
        tx: &DatabaseTransaction,
        plan: RevocationPlan,
    ) -> Result<(), delegation::Error> {
        let revoker = plan.revocation.0.revoker.clone();
        crate::space_purge_records::operation_actors(tx, &[&revoker]).await?;
        for item in plan.chain {
            delegation::process_carried(
                tx,
                &item,
                self.encryption.as_ref(),
                self.delegated_sql_caveats,
                self.named_keys,
            )
            .await?;
        }
        let serialization = plan.revocation.1;
        let id = hash(&serialization);
        let inserted =
            revocation::Entity::insert(revocation::ActiveModel::from(revocation::Model {
                id,
                serialization,
                revoker,
                revoked: plan.target,
                revoked_at: Some(OffsetDateTime::now_utc()),
            }))
            .on_conflict(
                OnConflict::column(revocation::Column::Id)
                    .do_nothing()
                    .to_owned(),
            )
            .exec_without_returning(tx)
            .await?;
        if inserted > 0 && !plan.revocation.0.parents.is_empty() {
            parent_delegations::Entity::insert_many(plan.revocation.0.parents.iter().map(|p| {
                parent_delegations::ActiveModel::from(parent_delegations::Model {
                    child: id,
                    parent: (*p).into(),
                })
            }))
            .exec_without_returning(tx)
            .await?;
        }
        crate::space_purge_records::request_for_records(tx, &[plan.target]).await?;
        Ok(())
    }

    /// The verified certificate of `network` with digest `subject` (hex).
    async fn stored_certificate<C: ConnectionTrait>(
        &self,
        db: &C,
        network: &NetworkId,
        subject: &str,
    ) -> Result<Option<VerifiedCertificate>, AcceptError> {
        let Some(row) = find_object(db, network, ObjectKind::Cert, subject).await? else {
            return Ok(None);
        };
        let signed = decode_cert(&row.bytes).ok_or_else(|| refused("certificate_malformed"))?;
        verify_certificate(&anchor(network)?, &signed, &NodeDidVerifier)
            .map(Some)
            .map_err(|_| refused("certificate_invalid"))
    }

    /// Revocations and key-state statements are held only by members: N's
    /// current certificate must name this node.
    async fn require_member(&self, network: &NetworkId) -> Result<(), AcceptError> {
        let member = current_certificate(&self.db, network)
            .await?
            .is_some_and(|current| {
                current
                    .body()
                    .members()
                    .iter()
                    .any(|member| member.node.as_str() == self.node_did)
            });
        if member {
            Ok(())
        } else {
            Err(AcceptError::Unavailable("not_a_member"))
        }
    }

    /// The member's state of key `path`: its row, reported `revoked` once the
    /// network is revoked.
    pub async fn key_view<C: ConnectionTrait>(
        &self,
        db: &C,
        network: &NetworkId,
        path: &str,
    ) -> Result<Option<KeyView>, DbErr> {
        let Some(row) =
            threshold_key_row::Entity::find_by_id((network.to_string(), path.to_string()))
                .one(db)
                .await?
        else {
            return Ok(None);
        };
        let revoked = network_revoked(db, network).await?;
        Ok(Some(KeyView {
            path: row.key_path,
            state_seq: row.state_seq as u64,
            state: if revoked {
                "revoked".to_string()
            } else {
                row.state
            },
            key_version: row.key_version as u64,
        }))
    }

    /// Signs the acknowledgement of a held object for a client nonce, which
    /// [`check_nonce`] accepts.
    pub fn ack(
        &self,
        network: &NetworkId,
        nonce: &str,
        accepted: &Accepted,
    ) -> Result<Ack, String> {
        check_nonce(nonce)?;
        let network = network.to_string();
        let outcome = "accepted";
        let preimage = ack_preimage(
            &network,
            nonce,
            &accepted.cid,
            outcome,
            accepted.key.as_ref(),
        );
        let signature = self
            .node_keypair
            .sign(&preimage)
            .map_err(|error| error.to_string())?;
        Ok(Ack {
            network,
            nonce: nonce.to_string(),
            cid: accepted.cid.clone(),
            outcome,
            key: accepted.key.clone(),
            node: self.node_did.clone(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        })
    }

    /// The `cert` and `activation` objects of `network`, which anyone may
    /// read: (kind, CID, bytes), in the order they were recorded.
    pub async fn chain(
        &self,
        network: &NetworkId,
    ) -> Result<Vec<(String, String, Vec<u8>)>, DbErr> {
        Ok(threshold_set_object::Entity::find()
            .filter(threshold_set_object::Column::NetworkId.eq(network.to_string()))
            .filter(
                threshold_set_object::Column::Kind
                    .is_in([ObjectKind::Cert.as_str(), ObjectKind::Activation.as_str()]),
            )
            .order_by_asc(threshold_set_object::Column::RecordedAt)
            .order_by_asc(threshold_set_object::Column::Cid)
            .all(&self.db)
            .await?
            .into_iter()
            .map(|row| (row.kind, row.cid, row.bytes))
            .collect())
    }
}

fn accepted(cid: &str, new: bool, key: Option<KeyView>) -> Accepted {
    Accepted {
        cid: cid.to_string(),
        new,
        key,
    }
}

fn anchor(network: &NetworkId) -> Result<TrustAnchor, AcceptError> {
    Ok(TrustAnchor {
        expected_owner: Did::new(network.owner_did()).map_err(|_| refused("network_invalid"))?,
        network: NetworkUrn::new(network.to_string()).map_err(|_| refused("network_invalid"))?,
    })
}

/// N's current certificate (gate B §5.5): the end of the activated chain
/// from N's activated genesis, each step a `verify_successor` with its own
/// activation. None without exactly one activated genesis. The walk stops
/// at a certificate with two activated successors (equivocation).
async fn current_certificate<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
) -> Result<Option<VerifiedCertificate>, AcceptError> {
    let objects = threshold_set_object::Entity::find()
        .filter(threshold_set_object::Column::NetworkId.eq(network.to_string()))
        .filter(
            threshold_set_object::Column::Kind
                .is_in([ObjectKind::Cert.as_str(), ObjectKind::Activation.as_str()]),
        )
        .all(db)
        .await?;
    let activated: BTreeSet<&str> = objects
        .iter()
        .filter(|object| object.kind == ObjectKind::Activation.as_str())
        .map(|object| object.subject.as_str())
        .collect();
    // One certificate per digest: encodings of one body share it.
    let certificates: BTreeMap<&str, SignedCertificate> = objects
        .iter()
        .filter(|object| {
            object.kind == ObjectKind::Cert.as_str() && activated.contains(object.subject.as_str())
        })
        .filter_map(|object| Some((object.subject.as_str(), decode_cert(&object.bytes)?)))
        .collect();
    let anchor = anchor(network)?;
    let mut geneses = certificates
        .values()
        .filter(|signed| signed.body.previous().is_none())
        .filter_map(|signed| verify_certificate(&anchor, signed, &NodeDidVerifier).ok());
    let (Some(mut current), None) = (geneses.next(), geneses.next()) else {
        return Ok(None);
    };
    // Each step raises the epoch, so the walk ends.
    loop {
        let step = {
            let mut successors = certificates
                .values()
                .filter_map(|signed| verify_successor(&current, signed, &NodeDidVerifier).ok());
            (successors.next(), successors.next())
        };
        match step {
            (Some(successor), None) => current = successor,
            _ => return Ok(Some(current)),
        }
    }
}

/// Gate B §4.3: a member creates N's network row and member rows from N's
/// activated genesis. A row already there must be this genesis's threshold
/// row; another row of N leaves the activation unavailable.
async fn create_network(
    tx: &DatabaseTransaction,
    network: &NetworkId,
    genesis: &VerifiedCertificate,
) -> Result<(), AcceptError> {
    let body = genesis.body();
    let public = body.public_material();
    let public_key = public.master_public_key().encode().to_vec();
    let now = now_rfc3339();
    encryption_network::Entity::insert(encryption_network::ActiveModel {
        network_id: Set(network.to_string()),
        owner_did: Set(network.owner_did().to_string()),
        name: Set(network.name().to_string()),
        alg: Set(THRESHOLD_ALG.to_string()),
        key_version: Set(1),
        public_key: Set(public_key.clone()),
        state: Set(NetworkState::Active.as_str().to_string()),
        threshold_n: Set(i32::from(public.threshold().n())),
        threshold_t: Set(i32::from(public.threshold().t())),
        key_backend: Set(KeyBackendKind::Threshold.as_str().to_string()),
        sealed_private_key: Set(None),
        created_at: Set(now.clone()),
        updated_at: Set(now.clone()),
    })
    .on_conflict(
        OnConflict::column(encryption_network::Column::NetworkId)
            .do_nothing()
            .to_owned(),
    )
    .exec_without_returning(tx)
    .await?;
    let row = encryption_network::Entity::find_by_id(network.to_string())
        .one(tx)
        .await?
        .ok_or_else(|| DbErr::RecordNotFound("encryption_network".to_string()))?;
    if row.key_backend != KeyBackendKind::Threshold.as_str() || row.public_key != public_key {
        return Err(AcceptError::Unavailable("network_exists"));
    }
    for member in body.members() {
        encryption_network_member::Entity::insert(encryption_network_member::ActiveModel {
            network_id: Set(network.to_string()),
            node_id: Set(member.node.as_str().to_string()),
            role: Set(MEMBER_ROLE.to_string()),
            share_index: Set(i32::from(member.index.get())),
            joined_at: Set(now.clone()),
        })
        .on_conflict(
            OnConflict::columns([
                encryption_network_member::Column::NetworkId,
                encryption_network_member::Column::NodeId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec_without_returning(tx)
        .await?;
    }
    Ok(())
}

async fn find_object<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
    kind: ObjectKind,
    subject: &str,
) -> Result<Option<threshold_set_object::Model>, DbErr> {
    threshold_set_object::Entity::find()
        .filter(threshold_set_object::Column::NetworkId.eq(network.to_string()))
        .filter(threshold_set_object::Column::Kind.eq(kind.as_str()))
        .filter(threshold_set_object::Column::Subject.eq(subject))
        .order_by_asc(threshold_set_object::Column::Cid)
        .one(db)
        .await
}

/// Adds an object; false when the set already held it.
async fn store<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
    cid: &str,
    kind: ObjectKind,
    subject: &str,
    bytes: &[u8],
) -> Result<bool, DbErr> {
    let inserted = threshold_set_object::Entity::insert(threshold_set_object::ActiveModel {
        network_id: Set(network.to_string()),
        cid: Set(cid.to_string()),
        kind: Set(kind.as_str().to_string()),
        subject: Set(subject.to_string()),
        bytes: Set(bytes.to_vec()),
        recorded_at: Set(now_rfc3339()),
    })
    .on_conflict(
        OnConflict::columns([
            threshold_set_object::Column::NetworkId,
            threshold_set_object::Column::Cid,
        ])
        .do_nothing()
        .to_owned(),
    )
    .exec_without_returning(db)
    .await?;
    Ok(inserted > 0)
}

async fn network_revoked<C: ConnectionTrait>(db: &C, network: &NetworkId) -> Result<bool, DbErr> {
    Ok(
        threshold_network_revocation::Entity::find_by_id(network.to_string())
            .one(db)
            .await?
            .is_some(),
    )
}

async fn record_fault<C: ConnectionTrait>(
    db: &C,
    network: &NetworkId,
    source: &str,
    cid: &str,
    reason: &str,
) -> Result<(), DbErr> {
    threshold_fault::Entity::insert(threshold_fault::ActiveModel {
        network_id: Set(network.to_string()),
        source_did: Set(source.to_string()),
        object_cid: Set(cid.to_string()),
        reason: Set(reason.to_string()),
        recorded_at: Set(now_rfc3339()),
        ..Default::default()
    })
    .exec_without_returning(db)
    .await?;
    Ok(())
}

/// The §4.3 merge of one `key.state` statement into its key row. The highest
/// `stateSeq` wins; a lower one changes nothing; an equal one with another
/// `(state, keyVersion)` blocks the key with `conflict` set until a higher
/// `stateSeq` arrives. Under a conflict the row keeps the highest key version
/// and the lowest statement CID, so every arrival order ends in one row.
/// Returns whether this statement is a conflict. The owner faults recorded do
/// depend on arrival order: a statement with one effect arriving after a
/// conflict at its `stateSeq` records another; the row does not.
async fn merge(
    tx: &DatabaseTransaction,
    network: &NetworkId,
    path: &str,
    cid: &str,
    state_seq: u64,
    state: StatementState,
    key_version: u64,
) -> Result<bool, DbErr> {
    let now = now_rfc3339();
    let key = (network.to_string(), path.to_string());
    let locked = || {
        threshold_key_row::Entity::find_by_id(key.clone())
            .lock_exclusive()
            .one(tx)
    };
    let seq = state_seq as i64;
    let version = key_version as i64;
    let row = match locked().await? {
        Some(row) => row,
        None => {
            let inserted = threshold_key_row::Entity::insert(threshold_key_row::ActiveModel {
                network_id: Set(key.0.clone()),
                key_path: Set(key.1.clone()),
                state: Set(state.as_str().to_string()),
                key_version: Set(version),
                state_seq: Set(seq),
                statement_cid: Set(cid.to_string()),
                conflict: Set(false),
                updated_at: Set(now.clone()),
            })
            .on_conflict(
                OnConflict::columns([
                    threshold_key_row::Column::NetworkId,
                    threshold_key_row::Column::KeyPath,
                ])
                .do_nothing()
                .to_owned(),
            )
            .exec_without_returning(tx)
            .await?;
            if inserted > 0 {
                return Ok(false);
            }
            // A concurrent statement inserted the row first: merge into it.
            locked()
                .await?
                .ok_or_else(|| DbErr::RecordNotFound("threshold_key_row".to_string()))?
        }
    };
    let update = |state: &str, version: i64, statement: &str, conflict: bool| {
        threshold_key_row::ActiveModel {
            network_id: Set(row.network_id.clone()),
            key_path: Set(row.key_path.clone()),
            state: Set(state.to_string()),
            key_version: Set(version),
            state_seq: Set(seq),
            statement_cid: Set(statement.to_string()),
            conflict: Set(conflict),
            updated_at: Set(now.clone()),
        }
    };
    if seq > row.state_seq {
        threshold_key_row::Entity::update(update(state.as_str(), version, cid, false))
            .exec(tx)
            .await?;
        return Ok(false);
    }
    if seq < row.state_seq {
        return Ok(false);
    }
    let statement = if cid < row.statement_cid.as_str() {
        cid
    } else {
        row.statement_cid.as_str()
    };
    if !row.conflict && row.state == state.as_str() && row.key_version == version {
        // Another statement with the same effect: only the lowest CID is kept.
        if statement != row.statement_cid {
            threshold_key_row::Entity::update(update(&row.state, version, statement, false))
                .exec(tx)
                .await?;
        }
        return Ok(false);
    }
    threshold_key_row::Entity::update(update(
        StatementState::Blocked.as_str(),
        row.key_version.max(version),
        statement,
        true,
    ))
    .exec(tx)
    .await?;
    Ok(true)
}

#[cfg(test)]
#[path = "threshold_set_tests.rs"]
mod tests;
