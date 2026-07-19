//! Strict, non-wire values shared by the exact-email N0a seam.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;

pub const KV_GET_ACTION: &str = "tinycloud.kv/get";
pub const SQL_READ_ACTION: &str = "tinycloud.sql/read";
pub const MARKDOWN_MEDIA_TYPE: &str = "text/markdown; charset=utf-8";
pub const MAX_MARKDOWN_BYTES: usize = 1_048_576;
pub const MAX_CID_BYTES: usize = 59;
pub const MAX_SHARE_ID_BYTES: usize = 128;
pub const MAX_DATABASE_NAME_BYTES: usize = 128;

/// KV CIDs copied literally from the pinned email-claim positive.json.
pub const KV_SHARE_CID: &str = "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4";
pub const KV_POLICY_CID: &str = "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4";

/// SQL CIDs copied literally from the pinned email-claim positive.json.
pub const SQL_SHARE_CID: &str = "bafkreif2kris7mo5etetu5jleg2noejza34ptwmpjhdm5jernutik6baqu";
pub const SQL_POLICY_CID: &str = "bafkreic6xkbiqtsv2wotzor7vjy6ri73ix5ntuwz4likrm3zhmxlpaajmq";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TypeError {
    #[error("invalid base64url {0}")]
    InvalidBase64(&'static str),
    #[error("invalid did")]
    InvalidDid,
    #[error("invalid canonical path")]
    InvalidPath,
    #[error("invalid database name")]
    InvalidDatabaseName,
    #[error("invalid named statement")]
    InvalidNamedStatement,
    #[error("invalid target origin")]
    InvalidTargetOrigin,
    #[error("invalid share CID")]
    InvalidShareCid,
    #[error("invalid share ID")]
    InvalidShareId,
    #[error("invalid policy CID")]
    InvalidPolicyCid,
    #[error("invalid share delegation CID")]
    InvalidShareDelegationCid,
    #[error("invalid authority material handle")]
    InvalidAuthorityMaterialHandle,
    #[error("invalid node delegation CID")]
    InvalidNodeDelegationCid,
    #[error("invalid safe JSON integer")]
    InvalidSafeJsonInteger,
}

fn redact(formatter: &mut fmt::Formatter<'_>, name: &str) -> fmt::Result {
    formatter.write_str(name)?;
    formatter.write_str("([REDACTED])")
}

/// A fixed-size SHA-256 digest represented as unpadded base64url.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        let bytes = URL_SAFE_NO_PAD
            .decode(value.as_bytes())
            .map_err(|_| TypeError::InvalidBase64("digest"))?;
        if bytes.len() != 32 || URL_SAFE_NO_PAD.encode(&bytes) != value {
            return Err(TypeError::InvalidBase64("digest"));
        }
        Ok(Self(value))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Sha256Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redact(formatter, "Sha256Digest")
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

macro_rules! fixed_base64_handle {
    ($name:ident, $length:expr) => {
        #[derive(Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                let bytes = URL_SAFE_NO_PAD
                    .decode(value.as_bytes())
                    .map_err(|_| TypeError::InvalidBase64(stringify!($name)))?;
                if bytes.len() != $length || URL_SAFE_NO_PAD.encode(&bytes) != value {
                    return Err(TypeError::InvalidBase64(stringify!($name)));
                }
                Ok(Self(value))
            }

            pub fn from_bytes(bytes: [u8; $length]) -> Self {
                Self(URL_SAFE_NO_PAD.encode(bytes))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                redact(formatter, stringify!($name))
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

fixed_base64_handle!(ProtocolNonce, 32);
fixed_base64_handle!(ProtocolJti, 16);
fixed_base64_handle!(SessionHandle, 16);

fn valid_did(value: &str) -> bool {
    let mut parts = value.splitn(3, ':');
    let (Some(prefix), Some(method), Some(identifier)) = (parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    if prefix != "did" || value.len() > 2048 {
        return false;
    }
    match method {
        "web" => valid_web_did_identifier(identifier),
        "pkh" => valid_pkh_did_identifier(identifier),
        "key" => valid_did_key_identifier(identifier),
        _ => false,
    }
}

fn valid_web_did_identifier(value: &str) -> bool {
    let mut segments = value.split(':');
    let Some(host) = segments.next() else {
        return false;
    };
    valid_dns_host(host)
        && segments.all(|segment| {
            !segment.is_empty()
                && segment.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'%')
                })
        })
}

fn valid_pkh_did_identifier(value: &str) -> bool {
    let parts: Vec<_> = value.split(':').collect();
    parts.len() >= 3
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'%')
                })
        })
}

fn valid_did_key_identifier(value: &str) -> bool {
    value.starts_with('z') && value.len() > 1 && base58_decode(&value[1..]).is_some()
}

fn base58_decode(value: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut bytes = vec![0u8];
    for character in value.bytes() {
        let digit = ALPHABET
            .iter()
            .position(|&candidate| candidate == character)? as u32;
        let mut carry = digit;
        for byte in bytes.iter_mut().rev() {
            let value = u32::from(*byte) * 58 + carry;
            *byte = value as u8;
            carry = value >> 8;
        }
        while carry != 0 {
            bytes.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let leading_zeroes = value.bytes().take_while(|&byte| byte == b'1').count();
    if bytes == [0] {
        bytes.clear();
    }
    let mut decoded = vec![0u8; leading_zeroes];
    decoded.extend(bytes);
    Some(decoded)
}

fn valid_did_key(value: &str) -> bool {
    let Some(multicodec) = value.strip_prefix("did:key:z") else {
        return false;
    };
    let Some(bytes) = base58_decode(multicodec) else {
        return false;
    };
    bytes.len() == 34 && bytes[0..2] == [0xed, 0x01]
}

macro_rules! validated_string {
    ($name:ident, $error:ident, $validator:expr) => {
        #[derive(Clone, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
                let value = value.into();
                if ($validator)(&value) {
                    Ok(Self(value))
                } else {
                    Err(TypeError::$error)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                redact(formatter, stringify!($name))
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
            }
        }
    };
}

fn valid_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.ends_with('/')
        && !value.contains("//")
        && !value.contains('\\')
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|character| !character.is_control() && !character.is_whitespace())
        })
}

fn valid_identifier(value: &str, max_len: usize, allow_dot: bool) -> bool {
    !value.is_empty()
        && value.len() <= max_len
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || byte == b'_'
                || byte == b'-'
                || (allow_dot && byte == b'.')
        })
}

fn valid_cid(value: &str) -> bool {
    value.len() == MAX_CID_BYTES
        && value.starts_with("bafkrei")
        && value
            .bytes()
            .skip(7)
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
}

fn valid_share_id(value: &str) -> bool {
    (1..=MAX_SHARE_ID_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'~' | b'-'))
}

fn valid_database_name(value: &str) -> bool {
    (1..=MAX_DATABASE_NAME_BYTES).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn valid_target_origin(value: &str) -> bool {
    let Some(authority) = value.strip_prefix("https://") else {
        return false;
    };
    if authority.is_empty() || authority.contains(['/', '?', '#', '@']) {
        return false;
    }

    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (authority, None),
    };

    if let Some(port) = port {
        if port.is_empty()
            || port.len() > 5
            || !port.bytes().all(|byte| byte.is_ascii_digit())
            || port.as_bytes()[0] == b'0'
        {
            return false;
        }
    }

    valid_target_host(host)
}

fn valid_target_host(value: &str) -> bool {
    !value.is_empty()
        && value.split('.').all(|label| {
            (1..=63).contains(&label.len())
                && is_ascii_lowercase_or_digit(label.as_bytes()[0])
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(|&byte| is_ascii_lowercase_or_digit(byte))
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn is_ascii_lowercase_or_digit(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit()
}

/*
 * The target-origin grammar is intentionally implemented directly rather than
 * by URL or integer parsers:
 * ^https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[1-9][0-9]{0,4})?$
 */

fn valid_dns_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
                && !label.starts_with('-')
                && !label.ends_with('-')
        })
}

validated_string!(Did, InvalidDid, valid_did);
validated_string!(Path, InvalidPath, valid_path);
validated_string!(DatabaseName, InvalidDatabaseName, valid_database_name);
validated_string!(NamedStatement, InvalidNamedStatement, |value: &str| {
    valid_identifier(value, 128, true)
});
validated_string!(TargetOrigin, InvalidTargetOrigin, valid_target_origin);
validated_string!(ShareCid, InvalidShareCid, valid_cid);
validated_string!(ShareId, InvalidShareId, valid_share_id);
validated_string!(PolicyCid, InvalidPolicyCid, valid_cid);
validated_string!(ShareDelegationCid, InvalidShareDelegationCid, valid_cid);
validated_string!(
    AuthorityMaterialHandle,
    InvalidAuthorityMaterialHandle,
    |value: &str| {
        (1..=128).contains(&value.len())
            && value.starts_with("amh_")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    }
);
validated_string!(NodeDelegationCid, InvalidNodeDelegationCid, valid_cid);
pub type Origin = TargetOrigin;

#[derive(Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct DidKey(String);

impl DidKey {
    pub fn parse(value: impl Into<String>) -> Result<Self, TypeError> {
        let value = value.into();
        if valid_did(&value) && valid_did_key(&value) {
            Ok(Self(value))
        } else {
            Err(TypeError::InvalidDid)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for DidKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        redact(formatter, "DidKey")
    }
}

impl<'de> Deserialize<'de> for DidKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::parse(String::deserialize(deserializer)?).map_err(D::Error::custom)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeJsonInteger(i64);

impl SafeJsonInteger {
    pub const MAX: i64 = 9_007_199_254_740_991;

    pub fn parse(value: i64) -> Result<Self, TypeError> {
        if value.unsigned_abs() <= Self::MAX as u64 {
            Ok(Self(value))
        } else {
            Err(TypeError::InvalidSafeJsonInteger)
        }
    }

    pub fn get(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SafeJsonInteger {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct IntegerVisitor;
        impl<'de> serde::de::Visitor<'de> for IntegerVisitor {
            type Value = SafeJsonInteger;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a JSON integer within the IEEE-754 safe range")
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                SafeJsonInteger::parse(value).map_err(E::custom)
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                i64::try_from(value)
                    .ok()
                    .and_then(|value| SafeJsonInteger::parse(value).ok())
                    .ok_or_else(|| E::custom(TypeError::InvalidSafeJsonInteger))
            }
        }
        deserializer.deserialize_i64(IntegerVisitor)
    }
}

impl fmt::Debug for SafeJsonInteger {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SafeJsonInteger([REDACTED])")
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KvGetAction {
    #[serde(rename = "tinycloud.kv/get")]
    Get,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SqlReadAction {
    #[serde(rename = "tinycloud.sql/read")]
    Read,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShareAction {
    #[serde(rename = "tinycloud.kv/get")]
    KvGet,
    #[serde(rename = "tinycloud.sql/read")]
    SqlRead,
}

impl fmt::Debug for ShareAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareAction([REDACTED])")
    }
}

pub type Action = ShareAction;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExactResource {
    #[serde(rename = "kv")]
    Kv { path: Path },
    #[serde(rename = "sql")]
    Sql {
        database: DatabaseName,
        path: Path,
        statement: NamedStatement,
    },
}

impl fmt::Debug for ExactResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kv { .. } => formatter.write_str("ExactResource::Kv { [REDACTED] }"),
            Self::Sql { .. } => formatter.write_str("ExactResource::Sql { [REDACTED] }"),
        }
    }
}

pub type Resource = ExactResource;

/// The frozen v1 source union. SQL is a named statement with structured
/// arguments; raw query text is deliberately not represented here.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
pub enum ContentSource {
    #[serde(rename = "kv")]
    Kv {
        action: KvGetAction,
        space: Did,
        path: Path,
    },
    #[serde(rename = "sql")]
    Sql {
        action: SqlReadAction,
        space: Did,
        database: DatabaseName,
        path: Path,
        statement: NamedStatement,
        arguments: BTreeMap<String, SafeJsonInteger>,
        #[serde(rename = "argumentsDigest")]
        arguments_digest: Sha256Digest,
    },
}

impl fmt::Debug for ContentSource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Kv { .. } => formatter.write_str("ContentSource::Kv { [REDACTED] }"),
            Self::Sql { .. } => formatter.write_str("ContentSource::Sql { [REDACTED] }"),
        }
    }
}

/// Independently bound identity, target origin, policy action, and exact resource.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareScope {
    pub share_cid: ShareCid,
    pub share_id: ShareId,
    pub delegation_cid: Option<ShareDelegationCid>,
    pub authority_material_handle: AuthorityMaterialHandle,
    pub authority_material_digest: Sha256Digest,
    pub policy_cid: PolicyCid,
    pub node_audience: Did,
    pub target_origin: TargetOrigin,
    pub action: ShareAction,
    pub resource: ExactResource,
    pub content_source: ContentSource,
    pub content_source_digest: Sha256Digest,
}

impl fmt::Debug for ShareScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareScope { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct HolderEquation {
    pub credential_subject: DidKey,
    pub presentation_holder: DidKey,
    pub presentation_signer: DidKey,
    pub policy_session_holder: DidKey,
    pub read_signer: DidKey,
}

impl fmt::Debug for HolderEquation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("HolderEquation { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct CredentialVerificationEvidence {
    pub issuer_did: Did,
    pub credential_subject: DidKey,
    pub disclosed_email: String,
    pub credential_digest: Sha256Digest,
    pub expires_at: i64,
}

impl fmt::Debug for CredentialVerificationEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CredentialVerificationEvidence")
            .field("issuer_did", &"[REDACTED]")
            .field("credential_subject", &"[REDACTED]")
            .field("disclosed_email", &"[REDACTED]")
            .field("credential_digest", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PolicySessionRequest {
    pub scope: ShareScope,
    pub holder: DidKey,
    pub credential_digest: Sha256Digest,
    pub nonce: ProtocolNonce,
    pub presentation_jti: ProtocolJti,
    pub challenge_id: String,
    pub challenge_request_digest: Sha256Digest,
    pub challenge_binding: serde_json::Value,
    pub policy_recipient_digest: Sha256Digest,
    pub credential_expires_at: i64,
}

impl fmt::Debug for PolicySessionRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicySessionRequest { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReadAuthorizationRequest {
    pub session: SessionHandle,
    pub jti: ProtocolJti,
    pub scope: ShareScope,
    pub holder: DidKey,
    pub request_body_digest: Sha256Digest,
}

impl fmt::Debug for ReadAuthorizationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadAuthorizationRequest { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct PolicySession {
    pub handle: SessionHandle,
    pub scope: ShareScope,
    pub holder: DidKey,
    pub credential_digest: Sha256Digest,
    pub sql_statement: Option<crate::share_email::data_plane::PinnedNamedStatement>,
}

impl fmt::Debug for PolicySession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PolicySession { [REDACTED] }")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct ReadInvocation {
    pub session: SessionHandle,
    pub jti: ProtocolJti,
    pub scope: ShareScope,
    pub holder: DidKey,
    pub request_body_digest: Sha256Digest,
}

impl fmt::Debug for ReadInvocation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ReadInvocation { [REDACTED] }")
    }
}

/// A read grant produced only by the #117 transaction boundary.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthorizedRead {
    session: PolicySession,
    invocation: ReadInvocation,
}

impl AuthorizedRead {
    pub(crate) fn from_parts(session: PolicySession, invocation: ReadInvocation) -> Self {
        Self {
            session,
            invocation,
        }
    }

    pub fn session(&self) -> &PolicySession {
        &self.session
    }

    pub fn invocation(&self) -> &ReadInvocation {
        &self.invocation
    }
}

impl fmt::Debug for AuthorizedRead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuthorizedRead { [REDACTED] }")
    }
}

/// Markdown bytes returned by an N3 adapter.
#[derive(Clone, PartialEq, Eq)]
pub struct MarkdownDocument(Vec<u8>);

impl fmt::Debug for MarkdownDocument {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("MarkdownDocument([REDACTED])")
    }
}

impl MarkdownDocument {
    pub fn from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLDER: &str = "did:key:z6MktwupdmLXVVqTzCw4i46r4uGyosGXRnR3XjN4Zq7oMMsw";
    const FROZEN_CID_PATTERN: &str = r"^bafkrei[a-z2-7]{52}$";
    const FROZEN_SHARE_ID_PATTERN: &str = r"^[A-Za-z0-9._~-]+$";
    const FROZEN_DATABASE_PATTERN: &str = r"^[A-Za-z0-9_-]+$";
    const FROZEN_STATEMENT_PATTERN: &str = r"^[A-Za-z][A-Za-z0-9_.-]*$";
    const FROZEN_ORIGIN_PATTERN: &str = r"^https://[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[1-9][0-9]{0,4})?$";

    #[test]
    fn strict_values_reject_invalid_and_overflow() {
        let noncanonical_cid = format!("{}1", &KV_SHARE_CID[..58]);
        let overlong_cid = format!("{KV_SHARE_CID}a");
        assert!(Did::parse("did:web:node.example").is_ok());
        assert!(Did::parse("did:web:node example").is_err());
        assert!(Did::parse("did:evil:node.example").is_err());
        assert!(Did::parse("did:web:").is_err());
        assert!(Did::parse("did:pkh:eip155:1:0xabc").is_ok());
        assert!(DidKey::parse(HOLDER).is_ok());
        assert!(DidKey::parse("did:key:zholder").is_err());
        assert!(Path::parse("documents/plan.md").is_ok());
        assert!(Path::parse("/documents/plan.md").is_err());
        assert!(Path::parse("documents/../plan.md").is_err());
        assert!(DatabaseName::parse("content_db").is_ok());
        assert!(DatabaseName::parse("9_content-db").is_ok());
        assert!(DatabaseName::parse("content.db").is_err());
        assert!(NamedStatement::parse("read_markdown").is_ok());
        assert!(NamedStatement::parse("SELECT * FROM docs").is_err());
        assert!(ShareCid::parse(KV_SHARE_CID).is_ok());
        assert!(PolicyCid::parse(KV_POLICY_CID).is_ok());
        assert!(ShareCid::parse(SQL_SHARE_CID).is_ok());
        assert!(PolicyCid::parse(SQL_POLICY_CID).is_ok());
        assert!(ShareCid::parse(&KV_SHARE_CID[..58]).is_err());
        assert!(ShareCid::parse(&overlong_cid).is_err());
        assert!(ShareCid::parse(KV_SHARE_CID.to_ascii_uppercase()).is_err());
        assert!(FROZEN_CID_PATTERN.starts_with("^bafkrei"));
        assert!(ShareCid::parse(&noncanonical_cid).is_err());
        assert!(ShareId::parse("share-01").is_ok());
        assert!(ShareId::parse("9.share_~-").is_ok());
        assert!(ShareId::parse("share/01").is_err());
        assert!(ShareId::parse("s".repeat(128)).is_ok());
        assert!(ShareId::parse("s".repeat(129)).is_err());
        assert!(DatabaseName::parse("9".repeat(128)).is_ok());
        assert!(DatabaseName::parse("9".repeat(129)).is_err());
        assert!(NamedStatement::parse(format!("a{}", "_".repeat(127))).is_ok());
        assert!(NamedStatement::parse(format!("a{}", "_".repeat(128))).is_err());
        assert!(NamedStatement::parse("9read").is_err());
        assert!(PolicyCid::parse(&overlong_cid).is_err());
        assert!(TargetOrigin::parse("https://node.example:8443").is_ok());
        assert!(TargetOrigin::parse("https://node.example").is_ok());
        assert!(TargetOrigin::parse("https://node.example:443").is_ok());
        assert!(TargetOrigin::parse("https://NODE.example").is_err());
        assert!(TargetOrigin::parse("https://node.example:0").is_err());
        assert!(TargetOrigin::parse("https://node.example:123456").is_err());
        assert!(TargetOrigin::parse("https://[::1]:8443").is_err());
        assert!(TargetOrigin::parse("https://[::1]oops").is_err());
        assert!(TargetOrigin::parse("https://user@node.example:8443").is_err());
        assert!(TargetOrigin::parse("https://node.example/path").is_err());
        assert!(TargetOrigin::parse("https://node.example?query").is_err());
        assert!(TargetOrigin::parse("https://node.example#fragment").is_err());
        assert!(FROZEN_SHARE_ID_PATTERN.contains("._~"));
        assert!(FROZEN_DATABASE_PATTERN.contains("A-Za-z0-9"));
        assert!(FROZEN_STATEMENT_PATTERN.starts_with("^[A-Za-z]"));
        assert!(FROZEN_ORIGIN_PATTERN.starts_with("^https://"));
        assert!(SafeJsonInteger::parse(SafeJsonInteger::MAX).is_ok());
        assert!(SafeJsonInteger::parse(SafeJsonInteger::MAX + 1).is_err());
        assert!(serde_json::from_str::<SafeJsonInteger>("9007199254740992").is_err());
        assert!(serde_json::from_str::<SafeJsonInteger>("1.0").is_err());
    }

    #[test]
    fn stable_identifiers_are_redacted_from_debug() {
        let scope = ShareScope {
            share_cid: ShareCid::parse(KV_SHARE_CID).unwrap(),
            share_id: ShareId::parse("share-secret-id").unwrap(),
            delegation_cid: None,
            authority_material_handle: AuthorityMaterialHandle::parse("amh_kv_001").unwrap(),
            authority_material_digest: Sha256Digest::from_bytes([0; 32]),
            policy_cid: PolicyCid::parse(KV_POLICY_CID).unwrap(),
            node_audience: Did::parse("did:web:node.example").unwrap(),
            target_origin: TargetOrigin::parse("https://node.example").unwrap(),
            action: ShareAction::KvGet,
            resource: ExactResource::Kv {
                path: Path::parse("documents/secret.md").unwrap(),
            },
            content_source: ContentSource::Kv {
                action: KvGetAction::Get,
                space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                    .unwrap(),
                path: Path::parse("documents/secret.md").unwrap(),
            },
            content_source_digest: Sha256Digest::from_bytes([0; 32]),
        };
        let debug = format!("{scope:?}");
        for secret in [
            KV_SHARE_CID,
            "share-secret-id",
            KV_POLICY_CID,
            "node.example",
            "secret.md",
        ] {
            assert!(!debug.contains(secret), "debug leaked {secret}: {debug}");
        }
    }

    #[test]
    fn content_source_serialization_is_action_bearing() {
        let source = ContentSource::Kv {
            action: KvGetAction::Get,
            space: Did::parse("did:pkh:eip155:1:0x1111111111111111111111111111111111111111")
                .unwrap(),
            path: Path::parse("documents/plan.md").unwrap(),
        };
        let serialized = serde_json::to_value(source).unwrap();
        assert_eq!(serialized["kind"], "kv");
        assert_eq!(serialized["action"], KV_GET_ACTION);
    }

    #[test]
    fn pinned_manifest_pairs_are_source_specific_and_reject_old_envelope_cids() {
        const OLD_ENVELOPE_PACKAGE_SHARE_CID: &str =
            "bafkreicvmdzkqzdtnlmynudck2a2ytmtketkdmlppk2q6owhzmndpcfnri";
        const OLD_ENVELOPE_PACKAGE_POLICY_CID: &str =
            "bafkreig36s2hz442yqcnkctpkgtjev5pyjngzymyipk3koywg4d7rqmu5u";

        assert_eq!(
            KV_SHARE_CID,
            "bafkreiekhtgxpb5xhykd6pytalpkmg52trryror2gritt7r56jv2t75fl4"
        );
        assert_eq!(
            KV_POLICY_CID,
            "bafkreiaqkcd56bhbn3zwcx7r5xdkle2nukcrhkvwwrcg4qqehk6q5hlwi4"
        );
        assert_eq!(
            SQL_SHARE_CID,
            "bafkreif2kris7mo5etetu5jleg2noejza34ptwmpjhdm5jernutik6baqu"
        );
        assert_eq!(
            SQL_POLICY_CID,
            "bafkreic6xkbiqtsv2wotzor7vjy6ri73ix5ntuwz4likrm3zhmxlpaajmq"
        );

        for manifest_cid in [KV_SHARE_CID, KV_POLICY_CID, SQL_SHARE_CID, SQL_POLICY_CID] {
            assert_ne!(manifest_cid, OLD_ENVELOPE_PACKAGE_SHARE_CID);
            assert_ne!(manifest_cid, OLD_ENVELOPE_PACKAGE_POLICY_CID);
        }
    }
}
