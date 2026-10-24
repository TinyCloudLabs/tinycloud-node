//! Owner-signed authorization for `tinycloud.encryption/key.delete`.
//!
//! `key.delete` is never a delegation. The delete route verifies the owner's
//! own credential itself and stores nothing in the delegation graph:
//!
//! - a `did:key` owner signs a UCAN invocation: invoker == owner, no proofs,
//!   exactly one capability (`key.delete` on the byte-equal key or prefix URN),
//!   `key-admin/v1` facts naming the node, network, body `keyPath` (a prefix
//!   keeps its trailing `/`), action and body hash;
//! - a `did:pkh:eip155` owner signs a SIWE CACAO whose ReCap is exactly
//!   `{ <key or prefix URN>: ["tinycloud.encryption/key.delete"] }`. A CACAO
//!   has no facts, so the request is bound through the signed message itself:
//!   the ReCap URN equals the URN the URL network id and the body `keyPath`
//!   name, the statement states the target, and `uri` names this node.
//!
//! Both forms share one lifetime rule and a one-time `(owner, nonce)` pair.

use serde::de::{Deserialize, Deserializer, Error as _};
use serde_json::Value;
use time::OffsetDateTime;
use tinycloud_auth::{
    authorization::{HeaderEncode, TinyCloudDelegation},
    cacaos::{
        siwe::{encode_eip55, Message},
        siwe_cacao::SiweCacao,
    },
    siwe_recap::{Capability as Recap, VerificationError, RESOURCE_PREFIX},
};

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    did_resolution::verify_ucan_signature, hash::hash, models::encryption_nonce,
    util::InvocationInfo,
};

use super::{
    canonical::canonical_hash,
    key_id::{self, EncryptionResource, KeyLocation},
    keys::network_of,
    network_id::NetworkId,
    protocol::{KeyAdminFacts, KEY_ADMIN_TYPE, KEY_DELETE_ACTION},
    service::{now_rfc3339, EncryptionService, EncryptionServiceError},
};

/// The SIWE `uri` of an owner delete names the node it is for.
pub const KEY_DELETE_URI_PREFIX: &str = "urn:tinycloud:encryption:key-delete:";
/// Longest `exp - iat` of an owner delete credential.
pub const MAX_LIFETIME_SECS: i64 = 300;
/// Tolerated clock skew for `iat` and `nbf`.
pub const CLOCK_SKEW_SECS: i64 = 30;
/// A consumed `(owner, nonce)` pair is kept this long after `exp`.
pub const NONCE_RETENTION_SECS: i64 = 30;
const MAX_NONCE_BYTES: usize = 256;

fn refuse(detail: &str) -> EncryptionServiceError {
    EncryptionServiceError::OwnerOnly(detail.to_string())
}

/// What a delete names: one key, or every key under `apps/<app id>/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTarget {
    location: KeyLocation,
    prefix: bool,
}

impl DeleteTarget {
    /// Parses the body `keyPath`. A path without a trailing `/` is one key. A
    /// path with exactly one trailing `/` is a prefix and must be
    /// `apps/<app id>/`: two segments, the first `apps`. Any other prefix is
    /// `key_path_invalid`.
    pub fn parse(network: &NetworkId, body_key_path: &str) -> Result<Self, EncryptionServiceError> {
        let invalid = |detail: &str| EncryptionServiceError::KeyPathInvalid(detail.to_string());
        let Some(stripped) = body_key_path.strip_suffix('/') else {
            let location = KeyLocation::new(network, body_key_path)
                .map_err(|err| EncryptionServiceError::KeyPathInvalid(err.to_string()))?;
            return Ok(Self {
                location,
                prefix: false,
            });
        };
        let urn = format!(
            "urn:tinycloud:encryption:{}:{}/{}/",
            network.owner_did(),
            network.name(),
            stripped
        );
        let Ok(EncryptionResource::KeyPrefix(location)) = key_id::parse(&urn) else {
            return Err(invalid("key path is not a valid key prefix"));
        };
        let mut segments = location.path().split('/');
        let app_prefix = matches!(
            (segments.next(), segments.next(), segments.next()),
            (Some("apps"), Some(_), None)
        );
        if !app_prefix || location.path() != stripped {
            return Err(invalid(
                "a prefix delete names exactly apps/<app id>/ (two segments and one trailing slash)",
            ));
        }
        Ok(Self {
            location,
            prefix: true,
        })
    }

    pub fn is_prefix(&self) -> bool {
        self.prefix
    }

    pub fn location(&self) -> &KeyLocation {
        &self.location
    }

    /// The body `keyPath`: the path, plus one trailing `/` for a prefix.
    pub fn key_path(&self) -> String {
        if self.prefix {
            format!("{}/", self.location.path())
        } else {
            self.location.path().to_string()
        }
    }

    /// The canonical resource URN the credential must name.
    pub fn urn(&self) -> String {
        if self.prefix {
            EncryptionResource::KeyPrefix(self.location.clone()).to_string()
        } else {
            EncryptionResource::Key(self.location.clone()).to_string()
        }
    }

    /// The SIWE statement the owner signs: the target, then the EIP-5573
    /// recap sentence for the one capability, joined by one space.
    pub fn siwe_statement(&self) -> Result<String, EncryptionServiceError> {
        let lead = if self.prefix {
            format!("Delete all TinyCloud keys under {}.", self.urn())
        } else {
            format!("Delete the TinyCloud key {}.", self.urn())
        };
        let mut recap = Recap::<Value>::default();
        recap
            .with_action_convert(
                self.urn(),
                KEY_DELETE_ACTION,
                Vec::<std::collections::BTreeMap<String, Value>>::new(),
            )
            .map_err(|_| refuse("the delete target cannot be stated"))?;
        Ok(format!("{lead} {}", recap.to_statement()))
    }
}

/// A ReCap caveat decoder that refuses every caveat value.
struct NoCaveat;

impl<'de> Deserialize<'de> for NoCaveat {
    fn deserialize<D: Deserializer<'de>>(_: D) -> Result<Self, D::Error> {
        Err(D::Error::custom("delete credentials carry no caveats"))
    }
}

/// A credential that passed every check. The caller consumes `(owner, nonce)`
/// before it acts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedOwnerDelete {
    pub owner: String,
    pub nonce: String,
    /// The credential's `exp` (unix seconds).
    pub exp: i64,
    /// CID of the credential bytes, the audit anchor of the delete.
    pub auth_cid: String,
}

enum Credential {
    Ucan(Box<InvocationInfo>),
    Cacao(Box<SiweCacao>),
}

fn decode_credential(header: &str) -> Result<(Credential, Vec<u8>), EncryptionServiceError> {
    let (delegation, canonical) = TinyCloudDelegation::decode(header)
        .map_err(|_| refuse("authorization is not a UCAN or a SIWE CACAO"))?;
    let credential = match delegation {
        TinyCloudDelegation::Ucan(ucan) => Credential::Ucan(Box::new(
            InvocationInfo::try_from(*ucan)
                .map_err(|_| refuse("invocation capabilities are malformed"))?,
        )),
        TinyCloudDelegation::Cacao(cacao) => Credential::Cacao(cacao),
    };
    Ok((credential, canonical))
}

/// The lifetime rule of a SIWE credential: `now < exp`, `0 < exp - iat <= 300 s`,
/// `iat <= now + 30 s` and `nbf <= now + 30 s`.
fn check_cacao_lifetime(
    iat: i64,
    nbf: Option<i64>,
    exp: i64,
    now: i64,
) -> Result<(), EncryptionServiceError> {
    if now >= exp {
        return Err(refuse("credential has expired"));
    }
    if iat > now + CLOCK_SKEW_SECS {
        return Err(refuse("credential is not yet valid"));
    }
    if exp <= iat {
        return Err(refuse("credential expires before it is issued"));
    }
    if exp - iat > MAX_LIFETIME_SECS {
        return Err(refuse("credential lifetime exceeds 300 seconds"));
    }
    if nbf.is_some_and(|nbf| nbf > now + CLOCK_SKEW_SECS) {
        return Err(refuse("credential is not yet valid"));
    }
    Ok(())
}

/// The lifetime rule of a UCAN credential. A UCAN has no `iat`, so it must
/// carry `nbf`, the time it was signed: `nbf <= now + 30 s`, `now < exp` and
/// `0 < exp - nbf <= 300 s`.
fn check_ucan_lifetime(nbf: Option<i64>, exp: i64, now: i64) -> Result<(), EncryptionServiceError> {
    let nbf = nbf.ok_or_else(|| refuse("a delete invocation must carry nbf"))?;
    if nbf > now + CLOCK_SKEW_SECS {
        return Err(refuse("credential is not yet valid"));
    }
    if now >= exp {
        return Err(refuse("credential has expired"));
    }
    if exp <= nbf {
        return Err(refuse("credential expires before it is valid"));
    }
    if exp - nbf > MAX_LIFETIME_SECS {
        return Err(refuse("credential lifetime exceeds 300 seconds"));
    }
    Ok(())
}

fn check_nonce(nonce: &str) -> Result<(), EncryptionServiceError> {
    if nonce.is_empty() || nonce.len() > MAX_NONCE_BYTES {
        return Err(refuse("credential nonce is missing or too long"));
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OwnerKind {
    DidKey,
    DidPkh,
}

fn owner_kind(owner: &str) -> Result<OwnerKind, EncryptionServiceError> {
    if owner.starts_with("did:key:") {
        Ok(OwnerKind::DidKey)
    } else if owner.starts_with("did:pkh:eip155:") {
        Ok(OwnerKind::DidPkh)
    } else {
        Err(refuse(
            "the network owner's DID method does not support key deletion",
        ))
    }
}

/// Verifies an owner delete credential against the request. Checks only; no
/// state changes. `now` is unix seconds.
pub async fn verify_owner_delete(
    header: &str,
    node_did: &str,
    network: &NetworkId,
    target: &DeleteTarget,
    body_value: &Value,
    now: i64,
) -> Result<VerifiedOwnerDelete, EncryptionServiceError> {
    // The URL network and the target name one network.
    if &network_of(target.location())? != network {
        return Err(refuse("the request network is not the target's network"));
    }
    let owner = network.owner_did();
    let (credential, canonical) = decode_credential(header)?;
    let auth_cid = hash(&canonical).to_cid(0x55).to_string();
    let (nonce, exp) = match (credential, owner_kind(owner)?) {
        (Credential::Ucan(info), OwnerKind::DidKey) => {
            verify_ucan(&info, node_did, network, target, body_value, now).await?
        }
        (Credential::Cacao(cacao), OwnerKind::DidPkh) => {
            verify_cacao(&cacao, node_did, target, now).await?
        }
        _ => {
            return Err(refuse(
                "the credential type does not match the network owner's DID method",
            ))
        }
    };
    Ok(VerifiedOwnerDelete {
        owner: owner.to_string(),
        nonce,
        exp,
        auth_cid,
    })
}

async fn verify_ucan(
    info: &InvocationInfo,
    node_did: &str,
    network: &NetworkId,
    target: &DeleteTarget,
    body_value: &Value,
    now: i64,
) -> Result<(String, i64), EncryptionServiceError> {
    verify_ucan_signature(&info.invocation)
        .await
        .map_err(|_| refuse("invocation signature is invalid"))?;
    if info.invoker != network.owner_did() {
        return Err(refuse("the invoker is not the network owner"));
    }
    if !info.parents.is_empty() {
        return Err(refuse("a delete invocation cites no proofs"));
    }
    let payload = info.invocation.payload();
    if payload.audience != node_did {
        return Err(refuse("the invocation audience is not this node"));
    }
    let [cap] = info.capabilities.as_slice() else {
        return Err(refuse("a delete invocation carries exactly one capability"));
    };
    if cap.ability.to_string() != KEY_DELETE_ACTION
        || cap.resource.to_string() != target.urn()
        || !cap.caveats.0.is_empty()
    {
        return Err(refuse(
            "the capability is not key.delete on exactly the requested target",
        ));
    }
    let fact = payload
        .facts
        .as_deref()
        .unwrap_or_default()
        .iter()
        .find(|fact| fact.get("type").and_then(Value::as_str) == Some(KEY_ADMIN_TYPE))
        .ok_or_else(|| refuse("key-admin facts are missing"))?;
    let facts: KeyAdminFacts = serde_json::from_value(fact.clone())
        .map_err(|_| refuse("key-admin facts are malformed"))?;
    if facts.target_node != node_did
        || &facts.network_id != network
        || facts.key_path != target.key_path()
        || facts.action != KEY_DELETE_ACTION
    {
        return Err(refuse("the key-admin facts do not match the request"));
    }
    if facts.body_hash != canonical_hash(body_value) {
        return Err(refuse("the key-admin bodyHash does not match the body"));
    }
    let exp = payload.expiration.as_seconds() as i64;
    let nbf = payload.not_before.map(|t| t.as_seconds() as i64);
    check_ucan_lifetime(nbf, exp, now)?;
    let nonce = payload.nonce.as_deref().unwrap_or_default();
    check_nonce(nonce)?;
    Ok((nonce.to_string(), exp))
}

async fn verify_cacao(
    cacao: &SiweCacao,
    node_did: &str,
    target: &DeleteTarget,
    now: i64,
) -> Result<(String, i64), EncryptionServiceError> {
    cacao
        .verify()
        .await
        .map_err(|_| refuse("SIWE signature is invalid"))?;
    let payload = cacao.payload();
    let message: Message = payload
        .clone()
        .try_into()
        .map_err(|_| refuse("SIWE issuer is not a did:pkh:eip155 account"))?;

    // The signer is the network owner: the issuer DID, rebuilt from the
    // signed chain id and address, equals the owner DID byte for byte.
    let signer = format!(
        "did:pkh:eip155:{}:0x{}",
        message.chain_id,
        encode_eip55(&message.address)
    );
    let target_owner = target.location().owner_did();
    if signer != target_owner {
        return Err(refuse("the SIWE signer is not the network owner"));
    }

    // The message carries exactly one resource: the ReCap.
    let [resource] = message.resources.as_slice() else {
        return Err(refuse("the SIWE message carries exactly one resource"));
    };
    if !resource.as_str().starts_with(RESOURCE_PREFIX) {
        return Err(refuse("the SIWE resource is not a ReCap"));
    }
    let recap = Recap::<NoCaveat>::extract_and_verify(&message)
        .map_err(|err| match err {
            VerificationError::IncorrectStatement(_) => {
                refuse("the SIWE statement does not state the delete")
            }
            VerificationError::Decoding(_) => {
                refuse("the SIWE ReCap is malformed or carries caveats")
            }
        })?
        .ok_or_else(|| refuse("the SIWE message carries no ReCap"))?;
    if !recap.proof().is_empty() {
        return Err(refuse("a delete ReCap cites no proofs"));
    }
    let mut capabilities = recap.abilities().iter();
    let (Some((urn, abilities)), None) = (capabilities.next(), capabilities.next()) else {
        return Err(refuse("the ReCap names exactly one resource"));
    };
    let mut names = abilities.keys();
    let (Some(ability), None) = (names.next(), names.next()) else {
        return Err(refuse("the ReCap names exactly one ability"));
    };
    // The ReCap URN equals the URN the URL network id and the body keyPath
    // name, byte for byte, trailing `/` included.
    if ability.to_string() != KEY_DELETE_ACTION || urn.as_str() != target.urn() {
        return Err(refuse(
            "the ReCap is not key.delete on exactly the requested target",
        ));
    }
    if message.uri.as_str() != format!("{KEY_DELETE_URI_PREFIX}{node_did}") {
        return Err(refuse("the SIWE uri does not name this node"));
    }
    if message.statement.as_deref() != Some(target.siwe_statement()?.as_str()) {
        return Err(refuse("the SIWE statement does not state the delete"));
    }

    let seconds = |t: &tinycloud_auth::cacaos::siwe::TimeStamp| -> i64 {
        let instant: &OffsetDateTime = t.as_ref();
        instant.unix_timestamp()
    };
    let iat = seconds(&message.issued_at);
    let exp = message
        .expiration_time
        .as_ref()
        .map(seconds)
        .ok_or_else(|| refuse("the SIWE message has no expiration"))?;
    let nbf = message.not_before.as_ref().map(seconds);
    check_cacao_lifetime(iat, nbf, exp, now)?;
    check_nonce(&message.nonce)?;
    Ok((message.nonce.clone(), exp))
}

impl EncryptionService {
    /// Verifies an owner delete credential and consumes its `(owner, nonce)`
    /// pair. The pair is consumed outside any later transaction, so a delete
    /// that fails afterwards still burns the signature. It is kept until
    /// `exp` plus [`NONCE_RETENTION_SECS`].
    pub async fn authorize_owner_delete(
        &self,
        header: &str,
        network: &NetworkId,
        target: &DeleteTarget,
        body_value: &Value,
    ) -> Result<VerifiedOwnerDelete, EncryptionServiceError> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let verified =
            verify_owner_delete(header, &self.node_did, network, target, body_value, now).await?;
        // Expired nonces are of no use: a credential past its `exp` is refused
        // before its nonce is looked at. Timestamps are RFC 3339 UTC and sort
        // as text.
        encryption_nonce::Entity::delete_many()
            .filter(encryption_nonce::Column::ExpiresAt.lt(now_rfc3339()))
            .exec(&self.db)
            .await?;
        self.consume_nonce_until(
            &verified.owner,
            &verified.nonce,
            verified.exp + NONCE_RETENTION_SECS,
        )
        .await
        .map_err(|err| match err {
            EncryptionServiceError::NonceReplay => refuse("the credential nonce was already used"),
            other => other,
        })?;
        Ok(verified)
    }
}
