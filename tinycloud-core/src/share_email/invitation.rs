//! Domain-separated invitation authorization receipts.
//!
//! This leaf intentionally contains no HTTP or application composition.  It
//! produces and verifies the five-minute node receipt; replay and durable
//! authority effects belong to [`super::state`].

use super::types::{
    ContentSource, Did, PolicyCid, ProtocolJti, Sha256Digest, ShareCid, ShareId, TargetOrigin,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use libp2p::identity::{Keypair, PublicKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{fmt, str::FromStr};
use time::{format_description::well_known::Rfc3339, Duration, OffsetDateTime};

pub const INVITATION_AUTHORIZATION_DOMAIN: &[u8] = b"xyz.tinycloud.share/invite-authorization/v1\0";
pub const INVITATION_AUTHORIZATION_TTL: Duration = Duration::seconds(300);
pub const RETURN_ORIGIN: &str = "https://share.tinycloud.xyz";
pub const MAX_INVITATION_BODY_BYTES: usize = 65_536;

/// Decode the opaque share-link token without accepting alternate encodings,
/// padding, or truncated/extended secrets.  The URL layer may add routing
/// metadata, but this token is always exactly the frozen 32-byte value.
pub fn decode_share_url_token(value: &str) -> Result<[u8; 32], InvitationError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.as_bytes())
        .map_err(|_| InvitationError::Invalid)?;
    bytes.try_into().map_err(|_| InvitationError::Invalid)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum InvitationError {
    #[error("invalid invitation authorization")]
    Invalid,
    #[error("invalid invitation signature")]
    Signature,
    #[error("invitation authorization expired")]
    Expired,
    #[error("invitation authorization body exceeds limit")]
    BodyTooLarge,
}

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct CanonicalEmail(String);

impl CanonicalEmail {
    pub fn parse(value: impl Into<String>) -> Result<Self, InvitationError> {
        let value = value.into();
        if !valid_email(&value) {
            return Err(InvitationError::Invalid);
        }
        let (local, domain) = value.split_once('@').ok_or(InvitationError::Invalid)?;
        let canonical = format!("{local}@{}", domain.to_ascii_lowercase());
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for CanonicalEmail {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for CanonicalEmail {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CanonicalEmail([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SenderTrust {
    Verified,
    Unverified,
}

impl fmt::Debug for SenderTrust {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SenderTrust([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct DocumentName(String);

impl DocumentName {
    pub fn parse(value: impl Into<String>) -> Result<Self, InvitationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 200
            || value
                .chars()
                .any(|character| character.is_control() || character == '\u{7f}')
        {
            return Err(InvitationError::Invalid);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for DocumentName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

impl fmt::Debug for DocumentName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DocumentName([REDACTED])")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationAuthorization {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    pub jti: ProtocolJti,
    pub sender_did: Did,
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub policy_cid: PolicyCid,
    pub recipient_email: CanonicalEmail,
    pub target_origin: TargetOrigin,
    pub node_audience: Did,
    pub return_origin: TargetOrigin,
    pub document_name: DocumentName,
    pub sender_trust: SenderTrust,
    pub content_source: ContentSource,
    pub content_source_digest: Sha256Digest,
    pub share_expires_at: String,
    pub issued_at: String,
    pub expires_at: String,
    pub report_abuse_token: ProtocolJti,
}

impl fmt::Debug for InvitationAuthorization {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationAuthorization { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationProof {
    pub alg: String,
    pub kid: String,
    pub signature: String,
}

impl fmt::Debug for InvitationProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationProof { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InvitationAuthorizationReceipt {
    pub authorization: InvitationAuthorization,
    pub proof: InvitationProof,
}

impl fmt::Debug for InvitationAuthorizationReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationAuthorizationReceipt { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct InvitationAuthorizationInput {
    pub jti: ProtocolJti,
    pub report_abuse_token: ProtocolJti,
    pub sender_did: Did,
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub policy_cid: PolicyCid,
    pub recipient_email: CanonicalEmail,
    pub target_origin: TargetOrigin,
    pub node_audience: Did,
    pub document_name: DocumentName,
    pub sender_trust: SenderTrust,
    pub content_source: ContentSource,
    pub content_source_digest: Sha256Digest,
    pub share_expires_at: String,
    pub request_body_digest: Sha256Digest,
}

impl fmt::Debug for InvitationAuthorizationInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InvitationAuthorizationInput { [REDACTED] }")
    }
}

pub trait InvitationSigner: Send + Sync {
    fn kid(&self) -> &str;
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, InvitationError>;
}

pub trait InvitationVerifier: Send + Sync {
    fn verify(&self, kid: &str, message: &[u8], signature: &[u8]) -> Result<(), InvitationError>;
}

pub struct Ed25519InvitationSigner {
    kid: String,
    keypair: Keypair,
}

impl Ed25519InvitationSigner {
    pub fn new(kid: impl Into<String>, keypair: Keypair) -> Result<Self, InvitationError> {
        let kid = kid.into();
        validate_kid(&kid)?;
        Ok(Self { kid, keypair })
    }
}

impl InvitationSigner for Ed25519InvitationSigner {
    fn kid(&self) -> &str {
        &self.kid
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, InvitationError> {
        self.keypair
            .sign(message)
            .map_err(|_| InvitationError::Signature)
    }
}

pub struct Ed25519InvitationVerifier {
    kid: String,
    public_key: PublicKey,
}

impl Ed25519InvitationVerifier {
    pub fn new(kid: impl Into<String>, public_key: PublicKey) -> Result<Self, InvitationError> {
        let kid = kid.into();
        validate_kid(&kid)?;
        Ok(Self { kid, public_key })
    }
}

impl InvitationVerifier for Ed25519InvitationVerifier {
    fn verify(&self, kid: &str, message: &[u8], signature: &[u8]) -> Result<(), InvitationError> {
        if kid != self.kid || signature.len() != 64 || !self.public_key.verify(message, signature) {
            return Err(InvitationError::Signature);
        }
        Ok(())
    }
}

pub fn issue_invitation_authorization(
    input: InvitationAuthorizationInput,
    signer: &dyn InvitationSigner,
    now: OffsetDateTime,
) -> Result<InvitationAuthorizationReceipt, InvitationError> {
    issue_invitation_authorization_for(
        input,
        signer,
        now,
        TargetOrigin::parse("https://node.example").map_err(|_| InvitationError::Invalid)?,
        Did::parse("did:web:node.example").map_err(|_| InvitationError::Invalid)?,
        TargetOrigin::parse(RETURN_ORIGIN).map_err(|_| InvitationError::Invalid)?,
    )
}

pub fn issue_invitation_authorization_for(
    input: InvitationAuthorizationInput,
    signer: &dyn InvitationSigner,
    now: OffsetDateTime,
    target_origin: TargetOrigin,
    node_audience: Did,
    return_origin: TargetOrigin,
) -> Result<InvitationAuthorizationReceipt, InvitationError> {
    let issued_at = canonical_timestamp(now)?;
    let share_expires_at = parse_timestamp(&input.share_expires_at)?;
    let expires_at = (now + INVITATION_AUTHORIZATION_TTL).min(share_expires_at);
    if expires_at <= now
        || input.target_origin != target_origin
        || input.node_audience != node_audience
    {
        return Err(InvitationError::Invalid);
    }
    let authorization = InvitationAuthorization {
        artifact_type: "TinyCloudShareInviteAuthorization".to_owned(),
        version: 1,
        jti: input.jti,
        sender_did: input.sender_did,
        share_cid: input.share_cid,
        share_id: input.share_id,
        policy_cid: input.policy_cid,
        recipient_email: input.recipient_email,
        target_origin,
        node_audience,
        return_origin,
        document_name: input.document_name,
        sender_trust: input.sender_trust,
        content_source: input.content_source,
        content_source_digest: input.content_source_digest,
        share_expires_at: input.share_expires_at,
        issued_at,
        expires_at: canonical_timestamp(expires_at)?,
        report_abuse_token: input.report_abuse_token,
    };
    validate_authorization_for(
        &authorization,
        now,
        &authorization.target_origin,
        &authorization.node_audience,
        &authorization.return_origin,
    )?;
    let message = signed_bytes(&authorization)?;
    let signature = signer.sign(&message)?;
    if signature.len() != 64 {
        return Err(InvitationError::Signature);
    }
    Ok(InvitationAuthorizationReceipt {
        authorization,
        proof: InvitationProof {
            alg: "EdDSA".to_owned(),
            kid: signer.kid().to_owned(),
            signature: URL_SAFE_NO_PAD.encode(signature),
        },
    })
}

pub fn verify_invitation_authorization(
    receipt: &InvitationAuthorizationReceipt,
    verifier: &dyn InvitationVerifier,
    now: OffsetDateTime,
) -> Result<Sha256Digest, InvitationError> {
    verify_invitation_authorization_for(
        receipt,
        verifier,
        now,
        &TargetOrigin::parse("https://node.example").map_err(|_| InvitationError::Invalid)?,
        &Did::parse("did:web:node.example").map_err(|_| InvitationError::Invalid)?,
        &TargetOrigin::parse(RETURN_ORIGIN).map_err(|_| InvitationError::Invalid)?,
    )
}

pub fn verify_invitation_authorization_for(
    receipt: &InvitationAuthorizationReceipt,
    verifier: &dyn InvitationVerifier,
    now: OffsetDateTime,
    target_origin: &TargetOrigin,
    node_audience: &Did,
    return_origin: &TargetOrigin,
) -> Result<Sha256Digest, InvitationError> {
    validate_authorization_for(
        &receipt.authorization,
        now,
        target_origin,
        node_audience,
        return_origin,
    )?;
    if receipt.proof.alg != "EdDSA" {
        return Err(InvitationError::Signature);
    }
    let signature = URL_SAFE_NO_PAD
        .decode(receipt.proof.signature.as_bytes())
        .map_err(|_| InvitationError::Signature)?;
    verifier.verify(
        &receipt.proof.kid,
        &signed_bytes(&receipt.authorization)?,
        &signature,
    )?;
    authorization_digest(receipt)
}

pub fn authorization_digest(
    receipt: &InvitationAuthorizationReceipt,
) -> Result<Sha256Digest, InvitationError> {
    let value = serde_json::to_value(receipt).map_err(|_| InvitationError::Invalid)?;
    let bytes = crate::policy_capability::jcs::canonicalize(&value);
    let mut digest = Sha256::new();
    digest.update(bytes);
    Ok(Sha256Digest::from_bytes(digest.finalize().into()))
}

pub fn signed_bytes(value: &InvitationAuthorization) -> Result<Vec<u8>, InvitationError> {
    let json = serde_json::to_value(value).map_err(|_| InvitationError::Invalid)?;
    let canonical = crate::policy_capability::jcs::canonicalize(&json);
    if canonical.len() > MAX_INVITATION_BODY_BYTES {
        return Err(InvitationError::BodyTooLarge);
    }
    let mut bytes = Vec::with_capacity(INVITATION_AUTHORIZATION_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(INVITATION_AUTHORIZATION_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(bytes)
}

fn validate_authorization_for(
    authorization: &InvitationAuthorization,
    now: OffsetDateTime,
    expected_target_origin: &TargetOrigin,
    expected_node_audience: &Did,
    expected_return_origin: &TargetOrigin,
) -> Result<(), InvitationError> {
    if authorization.artifact_type != "TinyCloudShareInviteAuthorization"
        || authorization.version != 1
        || authorization.return_origin != *expected_return_origin
        || authorization.target_origin != *expected_target_origin
        || authorization.node_audience != *expected_node_audience
        || authorization.jti == authorization.report_abuse_token
    {
        return Err(InvitationError::Invalid);
    }
    let issued_at = parse_timestamp(&authorization.issued_at)?;
    let expires_at = parse_timestamp(&authorization.expires_at)?;
    let share_expires_at = parse_timestamp(&authorization.share_expires_at)?;
    if issued_at > now + Duration::seconds(60)
        || expires_at <= now
        || expires_at > issued_at + INVITATION_AUTHORIZATION_TTL
        || expires_at > share_expires_at
        || issued_at >= expires_at
    {
        return Err(InvitationError::Expired);
    }
    validate_source(&authorization.content_source)?;
    let source = serde_json::to_value(&authorization.content_source)
        .map_err(|_| InvitationError::Invalid)?;
    let expected_digest = Sha256Digest::from_bytes(
        Sha256::digest(crate::policy_capability::jcs::canonicalize(&source)).into(),
    );
    if authorization.content_source_digest != expected_digest {
        return Err(InvitationError::Invalid);
    }
    Ok(())
}

fn validate_source(source: &ContentSource) -> Result<(), InvitationError> {
    match source {
        ContentSource::Kv { action, .. } if *action == super::types::KvGetAction::Get => Ok(()),
        ContentSource::Sql {
            action, arguments, ..
        } if *action == super::types::SqlReadAction::Read && arguments.len() <= 32 => Ok(()),
        _ => Err(InvitationError::Invalid),
    }
}

fn validate_kid(value: &str) -> Result<(), InvitationError> {
    let Some((did, fragment)) = value.split_once('#') else {
        return Err(InvitationError::Invalid);
    };
    if fragment.is_empty() || fragment.chars().any(|c| c.is_whitespace()) {
        return Err(InvitationError::Invalid);
    }
    Did::parse(did).map_err(|_| InvitationError::Invalid)?;
    Ok(())
}

fn valid_email(value: &str) -> bool {
    if value.len() < 3 || value.len() > 254 || !value.is_ascii() || value.matches('@').count() != 1
    {
        return false;
    }
    let (local, domain) = match value.split_once('@') {
        Some(parts) => parts,
        None => return false,
    };
    if !(1..=64).contains(&local.len()) || !(1..=253).contains(&domain.len()) {
        return false;
    }
    let atext = |byte: u8| byte.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~".contains(&byte);
    if local.starts_with('.')
        || local.ends_with('.')
        || local
            .split('.')
            .any(|part| part.is_empty() || !part.bytes().all(atext))
    {
        return false;
    }
    domain.split('.').all(|label| {
        (1..=63).contains(&label.len())
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && label
                .as_bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
    })
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, InvitationError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| InvitationError::Invalid)
}

fn canonical_timestamp(value: OffsetDateTime) -> Result<String, InvitationError> {
    let format = time::format_description::parse(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z",
    )
    .map_err(|_| InvitationError::Invalid)?;
    value.format(&format).map_err(|_| InvitationError::Invalid)
}

pub fn random_protocol_jti() -> ProtocolJti {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    ProtocolJti::from_bytes(bytes)
}

pub fn random_protocol_nonce() -> super::types::ProtocolNonce {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    super::types::ProtocolNonce::from_bytes(bytes)
}

pub fn canonical_json_digest(value: &Value) -> Sha256Digest {
    let bytes = crate::policy_capability::jcs::canonicalize(value);
    let mut digest = Sha256::new();
    digest.update(bytes);
    Sha256Digest::from_bytes(digest.finalize().into())
}

impl FromStr for CanonicalEmail {
    type Err = InvitationError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;

    #[test]
    fn canonical_email_preserves_local_and_lowercases_domain() {
        let email = CanonicalEmail::parse("Alice+Notes@EXAMPLE.com").unwrap();
        assert_eq!(email.as_str(), "Alice+Notes@example.com");
        assert!(CanonicalEmail::parse(" Alice@example.com").is_err());
        assert!(CanonicalEmail::parse("alice..notes@example.com").is_err());
        assert!(CanonicalEmail::parse("alice@example..com").is_err());
    }

    #[test]
    fn share_url_token_is_exactly_32_unpadded_bytes() {
        let token = URL_SAFE_NO_PAD.encode([7u8; 32]);
        assert_eq!(decode_share_url_token(&token).unwrap(), [7u8; 32]);
        assert!(decode_share_url_token(&URL_SAFE_NO_PAD.encode([7u8; 31])).is_err());
        assert!(decode_share_url_token(&format!("{}=", token)).is_err());
    }

    #[test]
    fn authorization_signature_is_domain_separated_and_redacted() {
        let keypair = Keypair::generate_ed25519();
        let signer =
            Ed25519InvitationSigner::new("did:web:node.example#invitation-key-1", keypair.clone())
                .unwrap();
        let input = InvitationAuthorizationInput {
            jti: ProtocolJti::from_bytes([1; 16]),
            report_abuse_token: ProtocolJti::from_bytes([2; 16]),
            sender_did: Did::parse("did:web:sender.example").unwrap(),
            share_cid: ShareCid::parse(super::super::types::KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-1").unwrap(),
            policy_cid: PolicyCid::parse(super::super::types::KV_POLICY_CID).unwrap(),
            recipient_email: CanonicalEmail::parse("Alice@example.com").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            document_name: DocumentName::parse("plan.md").unwrap(),
            sender_trust: SenderTrust::Verified,
            content_source: ContentSource::Kv {
                action: super::super::types::KvGetAction::Get,
                space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                    .unwrap(),
                path: super::super::types::Path::parse("documents/plan.md").unwrap(),
            },
            content_source_digest: Sha256Digest::from_bytes(
                Sha256::digest(crate::policy_capability::jcs::canonicalize(
                    &serde_json::to_value(&ContentSource::Kv {
                        action: super::super::types::KvGetAction::Get,
                        space: Did::parse(
                            "did:pkh:eip155:1:0x1111111111111111111111111111111111111111",
                        )
                        .unwrap(),
                        path: super::super::types::Path::parse("documents/plan.md").unwrap(),
                    })
                    .unwrap(),
                ))
                .into(),
            ),
            share_expires_at: "2030-01-01T00:00:00.000Z".to_owned(),
            request_body_digest: Sha256Digest::from_bytes([4; 32]),
        };
        let now = OffsetDateTime::parse("2029-01-01T00:00:00Z", &Rfc3339).unwrap();
        let receipt = issue_invitation_authorization(input, &signer, now).unwrap();
        let verifier = Ed25519InvitationVerifier::new(
            "did:web:node.example#invitation-key-1",
            keypair.public(),
        )
        .unwrap();
        verify_invitation_authorization(&receipt, &verifier, now).unwrap();
        assert!(!format!("{receipt:?}").contains("Alice@example.com"));
        assert!(!format!("{receipt:?}").contains("plan.md"));
        assert!(signed_bytes(&receipt.authorization)
            .unwrap()
            .starts_with(INVITATION_AUTHORIZATION_DOMAIN));
    }
}
