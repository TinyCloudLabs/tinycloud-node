//! Strict, non-wire values shared by the exact-email N0a seam.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fmt};
use thiserror::Error;
use time::OffsetDateTime;

pub const KV_GET_ACTION: &str = "tinycloud.kv/get";
pub const KV_METADATA_ACTION: &str = "tinycloud.kv/metadata";
pub const KV_LIST_ACTION: &str = "tinycloud.kv/list";
pub const KV_PUT_ACTION: &str = "tinycloud.kv/put";
pub const SQL_READ_ACTION: &str = "tinycloud.sql/read";
pub const MARKDOWN_MEDIA_TYPE: &str = "text/markdown; charset=utf-8";
pub const MAX_MARKDOWN_BYTES: usize = 1_048_576;
/// Addressed native KV content has the product-wide sharing ceiling. The
/// Markdown adapters intentionally retain their stricter validation boundary.
pub const MAX_NATIVE_SHARE_CONTENT_BYTES: usize = 100 * 1024 * 1024;
/// Native JSON carries content as base64url, so request and response ceilings
/// are separate from the plaintext product limit.
pub const MAX_NATIVE_ENCODED_REQUEST_BYTES: usize =
    (MAX_NATIVE_SHARE_CONTENT_BYTES / 3) * 4 + 2_000_000;
pub const MAX_NATIVE_RESPONSE_BYTES: usize = MAX_NATIVE_ENCODED_REQUEST_BYTES + 4_000_000;
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
    #[error("invalid recipient matcher")]
    InvalidRecipientMatcher,
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

/// A **delegation** CID, which may be blake3-addressed.
///
/// `valid_cid` above accepts only `bafkrei` — CIDv1/raw/**sha2-256** — which is
/// right for the documents this module content-addresses itself (share
/// envelopes, policies). Delegations are minted by the delegation layer and are
/// blake3-addressed, so they arrive as `bafkr4i`. This predicate was widened for
/// `NodeDelegationCid` and `ShareDelegationCid` was left on `valid_cid`, so
/// every addressed claim on production failed: `typed_scope` could not parse the
/// owner delegation CID
/// (`bafkr4iaickipp4ceomv46xkot4ujivcogxhmvf6xiqhqpvuuxz2urxrt7u`) and the node
/// answered a flat `403 policy_denied` (TC-451).
fn valid_delegation_cid(value: &str) -> bool {
    value.len() == MAX_CID_BYTES
        && (value.starts_with("bafkrei") || value.starts_with("bafkr4"))
        && value
            .bytes()
            .skip(if value.starts_with("bafkrei") { 7 } else { 6 })
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
validated_string!(
    ShareDelegationCid,
    InvalidShareDelegationCid,
    valid_delegation_cid
);
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
validated_string!(
    NodeDelegationCid,
    InvalidNodeDelegationCid,
    valid_delegation_cid
);
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
    #[serde(rename = "tinycloud.kv/list")]
    List,
    #[serde(rename = "tinycloud.kv/put")]
    Put,
}

impl KvGetAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => KV_GET_ACTION,
            Self::List => KV_LIST_ACTION,
            Self::Put => KV_PUT_ACTION,
        }
    }
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
    #[serde(rename = "tinycloud.kv/metadata")]
    KvMetadata,
    #[serde(rename = "tinycloud.kv/list")]
    KvList,
    #[serde(rename = "tinycloud.kv/put")]
    KvPut,
    #[serde(rename = "tinycloud.sql/read")]
    SqlRead,
}

impl ShareAction {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KvGet => KV_GET_ACTION,
            Self::KvMetadata => KV_METADATA_ACTION,
            Self::KvList => KV_LIST_ACTION,
            Self::KvPut => KV_PUT_ACTION,
            Self::SqlRead => SQL_READ_ACTION,
        }
    }

    pub const fn is_kv(self) -> bool {
        matches!(
            self,
            Self::KvGet | Self::KvMetadata | Self::KvList | Self::KvPut
        )
    }

    pub const fn is_list(self) -> bool {
        matches!(self, Self::KvList)
    }

    pub const fn is_edit(self) -> bool {
        matches!(self, Self::KvPut)
    }
}

/// The recipient authorization matcher is deliberately separate from the
/// delivery address.  A domain policy is matched only against the complete
/// `/email` disclosure authenticated by the OpenCredentials verifier.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", deny_unknown_fields)]
pub enum RecipientMatcher {
    #[serde(rename = "exactEmail")]
    ExactEmail(String),
    #[serde(rename = "emailDomain")]
    EmailDomain(String),
    #[serde(rename = "recipientDid")]
    RecipientDid(String),
}

impl RecipientMatcher {
    pub fn canonical(&self) -> Result<String, TypeError> {
        match self {
            Self::ExactEmail(value) => tinycloud_auth::share_email_evidence::normalize_email(value)
                .map(|value| format!("exactEmail:{value}"))
                .map_err(|_| TypeError::InvalidRecipientMatcher),
            Self::EmailDomain(value) => {
                tinycloud_auth::share_email_evidence::normalize_policy_domain(value)
                    .map(|value| format!("emailDomain:{value}"))
                    .map_err(|_| TypeError::InvalidRecipientMatcher)
            }
            Self::RecipientDid(value) => Did::parse(value.clone())
                .map(|value| format!("recipientDid:{}", value.as_str()))
                .map_err(|_| TypeError::InvalidRecipientMatcher),
        }
    }

    /// Preserve the v1 exact-email digest preimage while giving v2 domain
    /// matchers a distinct canonical preimage.
    pub fn digest_material(&self) -> Result<String, TypeError> {
        match self {
            Self::ExactEmail(value) => tinycloud_auth::share_email_evidence::normalize_email(value)
                .map_err(|_| TypeError::InvalidRecipientMatcher),
            Self::EmailDomain(_) | Self::RecipientDid(_) => self.canonical(),
        }
    }

    /// V2 policy and invitation artifacts carry the normalized matcher, not
    /// merely a matcher that can be normalized later.  This keeps the signed
    /// bytes and the value consumed by Share/OpenCredentials identical.
    pub fn is_canonical(&self) -> bool {
        match self {
            Self::ExactEmail(value) => tinycloud_auth::share_email_evidence::normalize_email(value)
                .is_ok_and(|normalized| normalized == *value),
            Self::EmailDomain(value) => {
                tinycloud_auth::share_email_evidence::normalize_policy_domain(value)
                    .is_ok_and(|normalized| normalized == *value)
            }
            Self::RecipientDid(value) => {
                Did::parse(value.clone()).is_ok_and(|normalized| normalized.as_str() == value)
            }
        }
    }

    pub fn matches_verified_email(&self, verified_email: &str) -> bool {
        match self {
            Self::ExactEmail(expected) => {
                tinycloud_auth::share_email_evidence::normalize_email(expected)
                    .ok()
                    .zip(tinycloud_auth::share_email_evidence::normalize_email(verified_email).ok())
                    .is_some_and(|(expected, actual)| expected == actual)
            }
            Self::EmailDomain(expected) => {
                tinycloud_auth::share_email_evidence::normalize_email_domain(verified_email)
                    .ok()
                    .zip(
                        tinycloud_auth::share_email_evidence::normalize_policy_domain(expected)
                            .ok(),
                    )
                    .is_some_and(|(expected, actual)| expected == actual)
            }
            Self::RecipientDid(_) => false,
        }
    }

    pub fn is_domain(&self) -> bool {
        matches!(self, Self::EmailDomain(_))
    }

    pub fn is_recipient_did(&self) -> bool {
        matches!(self, Self::RecipientDid(_))
    }

    pub fn recipient_did(&self) -> Option<&str> {
        match self {
            Self::RecipientDid(value) => Some(value),
            _ => None,
        }
    }
}

impl fmt::Debug for RecipientMatcher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactEmail(_) => formatter.write_str("RecipientMatcher::ExactEmail([REDACTED])"),
            Self::EmailDomain(_) => {
                formatter.write_str("RecipientMatcher::EmailDomain([REDACTED])")
            }
            Self::RecipientDid(_) => {
                formatter.write_str("RecipientMatcher::RecipientDid([REDACTED])")
            }
        }
    }
}

impl fmt::Debug for ShareAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareAction([REDACTED])")
    }
}

/// The canonical resource ceiling used by v2 share policy state.  Keeping
/// this as a typed object prevents callers from smuggling the browser's
/// `{kind,path}` shape (or an untyped string) into the authority CID.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SharePolicyResource {
    pub kind: SharePolicyResourceKind,
    pub value: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SharePolicyResourceKind {
    Exact,
    Prefix,
}

impl fmt::Debug for SharePolicyResource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharePolicyResource { [REDACTED] }")
    }
}

impl fmt::Debug for SharePolicyResourceKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharePolicyResourceKind([REDACTED])")
    }
}

/// Canonical v2 policy state emitted by the Node authority boundary.
///
/// This is deliberately stricter than the v1 compatibility state: all keys
/// are fixed, actions are typed, and resources use `{kind,value}`.  The
/// canonical JSON bytes of this value are the Share policy CID preimage.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SharePolicyV2 {
    #[serde(rename = "type")]
    pub artifact_type: String,
    pub version: u8,
    pub recipient_matcher: RecipientMatcher,
    pub content_source: ContentSource,
    pub content_source_digest: Sha256Digest,
    pub actions: Vec<ShareAction>,
    pub resource: SharePolicyResource,
    pub expires_at: String,
    pub issuer_did: Did,
}

impl fmt::Debug for SharePolicyV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SharePolicyV2 { [REDACTED] }")
    }
}

impl SharePolicyV2 {
    pub fn validate(&self) -> Result<(), TypeError> {
        if self.artifact_type != "TinyCloudSharePolicy"
            || self.version != 2
            || self.actions.is_empty()
            || self
                .actions
                .windows(2)
                .any(|pair| pair[0].as_str() >= pair[1].as_str())
            || self
                .actions
                .iter()
                .any(|action| matches!(action, ShareAction::SqlRead))
                && self.actions.len() > 1
        {
            return Err(TypeError::InvalidRecipientMatcher);
        }
        let source_path = match &self.content_source {
            ContentSource::Kv { path, .. } | ContentSource::Sql { path, .. } => path,
        };
        if match &self.content_source {
            ContentSource::Kv { .. } => self.actions.iter().any(|action| !action.is_kv()),
            ContentSource::Sql { .. } => self.actions != [ShareAction::SqlRead],
        } {
            return Err(TypeError::InvalidRecipientMatcher);
        }
        if !self.recipient_matcher.is_canonical() {
            return Err(TypeError::InvalidRecipientMatcher);
        }
        let source_value = serde_json::to_value(&self.content_source)
            .map_err(|_| TypeError::InvalidRecipientMatcher)?;
        let source_digest = Sha256Digest::from_bytes(
            Sha256::digest(crate::policy_capability::jcs::canonicalize(&source_value)).into(),
        );
        if source_digest != self.content_source_digest {
            return Err(TypeError::InvalidRecipientMatcher);
        }
        let expiry = OffsetDateTime::parse(
            &self.expires_at,
            &time::format_description::well_known::Rfc3339,
        )
        .map_err(|_| TypeError::InvalidRecipientMatcher)?;
        let canonical_expiry = expiry
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|_| TypeError::InvalidRecipientMatcher)?;
        let canonical_millis_expiry = format!(
            "{}.000Z",
            canonical_expiry
                .strip_suffix('Z')
                .ok_or(TypeError::InvalidRecipientMatcher)?
        );
        if self.expires_at != canonical_expiry && self.expires_at != canonical_millis_expiry {
            return Err(TypeError::InvalidRecipientMatcher);
        }
        if self.resource.value.is_empty() {
            if self.resource.kind != SharePolicyResourceKind::Prefix
                || !source_path.as_str().is_empty()
            {
                return Err(TypeError::InvalidPath);
            }
        } else {
            let path = Path::parse(self.resource.value.clone())?;
            validate_share_path(&path, false)?;
            if !same_or_descendant_path(source_path, &path) {
                return Err(TypeError::InvalidPath);
            }
        }
        Ok(())
    }
}

fn same_or_descendant_path(prefix: &Path, candidate: &Path) -> bool {
    prefix.as_str() == candidate.as_str()
        || candidate
            .as_str()
            .strip_prefix(prefix.as_str())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub type Action = ShareAction;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExactResource {
    #[serde(rename = "kv")]
    Kv { path: Path },
    #[serde(rename = "kvPrefix")]
    KvPrefix { path: Path },
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
            Self::KvPrefix { .. } => formatter.write_str("ExactResource::KvPrefix { [REDACTED] }"),
            Self::Sql { .. } => formatter.write_str("ExactResource::Sql { [REDACTED] }"),
        }
    }
}

/// Validate the segment-aware path contract used by share scopes. The generic
/// `Path` type intentionally remains permissive for legacy capability APIs;
/// share authorization must reject traversal, empty segments, and ambiguous
/// slash forms before a scope reaches the authority kernel.
pub fn validate_share_path(path: &Path, allow_root: bool) -> Result<(), TypeError> {
    let value = path.as_str();
    if value.is_empty() {
        return allow_root.then_some(()).ok_or(TypeError::InvalidPath);
    }
    if value.starts_with('/')
        || value.ends_with('/')
        || value.contains("//")
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte == b'\\')
    {
        return Err(TypeError::InvalidPath);
    }
    if value
        .split('/')
        .any(|segment| segment.is_empty() || matches!(segment, "." | ".."))
    {
        return Err(TypeError::InvalidPath);
    }
    Ok(())
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
    /// The authenticated policy action ceiling. `action` is the operation
    /// selected for this request; this set permits only bounded attenuation.
    pub allowed_actions: Vec<ShareAction>,
    pub resource: ExactResource,
    pub content_source: ContentSource,
    pub content_source_digest: Sha256Digest,
}

/// Return true only when `candidate` is the immediate child of `prefix`.
pub fn is_direct_child_path(prefix: &Path, candidate: &Path) -> bool {
    let remainder = if prefix.as_str().is_empty() {
        candidate.as_str()
    } else {
        candidate
            .as_str()
            .strip_prefix(&format!("{}/", prefix.as_str()))
            .unwrap_or("")
    };
    !remainder.is_empty() && !remainder.contains('/')
}

/// Opaque, scope-bound direct-child cursor. It intentionally contains only
/// digests and a lexical position; decoding requires the caller to compare all
/// binding fields with the currently verified session before using `last`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ShareCursor {
    pub version: u8,
    pub subject_digest: Sha256Digest,
    pub scope_digest: Sha256Digest,
    pub source_digest: Sha256Digest,
    pub action: ShareAction,
    pub prefix: Path,
    pub limit: u16,
    pub last: Path,
    /// Node-authenticated cursors carry a MAC.  The optional form keeps the
    /// legacy in-memory constructor usable for protocol fixtures; production
    /// HTTP handlers must require and verify this field before using `last`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<Sha256Digest>,
}

impl fmt::Debug for ShareCursor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ShareCursor { [REDACTED] }")
    }
}

impl ShareCursor {
    pub fn new(scope: &ShareScope, holder: &DidKey, limit: usize, last: Path) -> Self {
        let scope_bytes = crate::policy_capability::jcs::canonicalize(
            &serde_json::to_value(scope).expect("share scope serializes"),
        );
        let scope_digest = Sha256Digest::from_bytes(Sha256::digest(scope_bytes).into());
        let subject_digest = Sha256Digest::from_bytes(Sha256::digest(holder.as_str()).into());
        Self {
            version: 1,
            subject_digest,
            scope_digest,
            source_digest: scope.content_source_digest.clone(),
            action: scope.action,
            prefix: match &scope.resource {
                ExactResource::Kv { path }
                | ExactResource::KvPrefix { path }
                | ExactResource::Sql { path, .. } => path.clone(),
            },
            limit: limit.min(u16::MAX as usize) as u16,
            last,
            mac: None,
        }
    }

    pub fn matches(&self, scope: &ShareScope, holder: &DidKey, limit: usize) -> bool {
        let expected = Self::new(scope, holder, limit, self.last.clone());
        self.version == 1
            && self.subject_digest == expected.subject_digest
            && self.scope_digest == expected.scope_digest
            && self.source_digest == expected.source_digest
            && self.action == expected.action
            && self.prefix == expected.prefix
            && self.limit == expected.limit
            && validate_share_path(&self.last, false).is_ok()
    }

    pub fn encode(&self) -> Result<String, TypeError> {
        let bytes = crate::policy_capability::jcs::canonicalize(
            &serde_json::to_value(self).map_err(|_| TypeError::InvalidBase64("cursor"))?,
        );
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    pub fn decode(value: &str) -> Result<Self, TypeError> {
        if value.len() > 4096 {
            return Err(TypeError::InvalidBase64("cursor"));
        }
        let bytes = URL_SAFE_NO_PAD
            .decode(value)
            .map_err(|_| TypeError::InvalidBase64("cursor"))?;
        let cursor: Self =
            serde_json::from_slice(&bytes).map_err(|_| TypeError::InvalidBase64("cursor"))?;
        let canonical = cursor.encode()?;
        if cursor.version != 1
            || cursor.limit == 0
            || validate_share_path(&cursor.prefix, true).is_err()
            || validate_share_path(&cursor.last, false).is_err()
            || canonical != value
        {
            return Err(TypeError::InvalidBase64("cursor"));
        }
        Ok(cursor)
    }
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
    pub holder_binding_jti: ProtocolJti,
    pub holder_binding_expires_at: i64,
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

/// The only admission value accepted by the authority transaction. Its
/// fields can be populated only by the concrete verifier after exact-email
/// and holder-binding checks have succeeded.
pub struct VerifiedSessionAdmission {
    request: PolicySessionRequest,
    verified_email: String,
    verified_credential_digest: Sha256Digest,
    holder_equation: HolderEquation,
}

impl VerifiedSessionAdmission {
    pub(crate) fn from_verified(
        request: PolicySessionRequest,
        verified_email: String,
        verified_credential_digest: Sha256Digest,
        holder_equation: HolderEquation,
    ) -> Self {
        Self {
            request,
            verified_email,
            verified_credential_digest,
            holder_equation,
        }
    }

    pub(crate) fn request(&self) -> &PolicySessionRequest {
        &self.request
    }

    pub(crate) fn verified_email(&self) -> &str {
        &self.verified_email
    }

    pub(crate) fn verified_credential_digest(&self) -> &Sha256Digest {
        &self.verified_credential_digest
    }

    pub(crate) fn holder_equation(&self) -> &HolderEquation {
        &self.holder_equation
    }

    #[cfg(test)]
    pub(crate) fn for_test(request: PolicySessionRequest, holder: DidKey) -> Self {
        Self::from_verified(
            request,
            "holder@example.com".to_owned(),
            Sha256Digest::from_bytes([9; 32]),
            HolderEquation {
                credential_subject: holder.clone(),
                presentation_holder: holder.clone(),
                presentation_signer: holder.clone(),
                policy_session_holder: holder.clone(),
                read_signer: holder,
                holder_binding_jti: ProtocolJti::from_bytes([8; 16]),
                holder_binding_expires_at: i64::MAX,
            },
        )
    }
}

impl fmt::Debug for VerifiedSessionAdmission {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("VerifiedSessionAdmission { [REDACTED] }")
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
    pub expires_at: OffsetDateTime,
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
        assert!(validate_share_path(&Path::parse("folder").unwrap(), false).is_ok());
        assert!(validate_share_path(&Path::parse("folder").unwrap(), true).is_ok());
        assert!(Path::parse("folder/../secret").is_err());
        assert!(Path::parse("folder//child").is_err());
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
    fn recipient_did_matchers_are_canonical_and_method_validated() {
        let key = RecipientMatcher::RecipientDid(HOLDER.to_owned());
        assert_eq!(key.canonical().unwrap(), format!("recipientDid:{HOLDER}"));
        assert!(key.is_canonical());
        assert!(
            RecipientMatcher::RecipientDid("did:web:recipient.example:path".to_owned())
                .is_canonical()
        );
        assert!(RecipientMatcher::RecipientDid("did:pkh:eip155:1:0xabc".to_owned()).is_canonical());
        assert!(!RecipientMatcher::RecipientDid("did:key:zholder".to_owned()).is_canonical());
        assert!(
            !RecipientMatcher::RecipientDid("did:web:-recipient.example".to_owned()).is_canonical()
        );
        assert!(!RecipientMatcher::RecipientDid("did:pkh:eip155:1".to_owned()).is_canonical());
        assert!(!key.matches_verified_email("person@example.com"));
    }

    #[test]
    fn v2_policy_is_canonical_and_rejects_browser_resource_shapes() {
        let source = serde_json::json!({
            "kind": "kv",
            "action": "tinycloud.kv/get",
            "space": "did:web:space.example",
            "path": "documents"
        });
        let source_digest = Sha256Digest::from_bytes(
            Sha256::digest(crate::policy_capability::jcs::canonicalize(&source)).into(),
        );
        let value = serde_json::json!({
            "type": "TinyCloudSharePolicy",
            "version": 2,
            "recipientMatcher": {"kind": "emailDomain", "value": "example.com"},
            "contentSource": source,
            "contentSourceDigest": source_digest,
            "actions": ["tinycloud.kv/get"],
            "resource": {"kind": "prefix", "value": "documents"},
            "expiresAt": "2027-01-01T00:00:00Z",
            "issuerDid": "did:web:sender.example"
        });
        let policy: SharePolicyV2 = serde_json::from_value(value.clone()).unwrap();
        assert!(policy.validate().is_ok());

        let mut browser_shape = value;
        browser_shape["resource"] = serde_json::json!({
            "kind": "prefix",
            "path": "documents"
        });
        assert!(serde_json::from_value::<SharePolicyV2>(browser_shape).is_err());

        let mut unknown = serde_json::to_value(policy).unwrap();
        unknown["target"] = serde_json::json!("https://share.example");
        assert!(serde_json::from_value::<SharePolicyV2>(unknown).is_err());
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
            allowed_actions: vec![ShareAction::KvGet],
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
        let holder = DidKey::parse(HOLDER).unwrap();
        let cursor = ShareCursor::new(
            &scope,
            &holder,
            25,
            Path::parse("documents/secret.md").unwrap(),
        );
        let encoded = cursor.encode().unwrap();
        assert!(!encoded.contains("documents"));
        let decoded = ShareCursor::decode(&encoded).unwrap();
        assert!(decoded.matches(&scope, &holder, 25));
        let mut changed = scope.clone();
        changed.action = ShareAction::KvPut;
        assert!(!decoded.matches(&changed, &holder, 25));
        assert!(ShareCursor::decode(&format!("{encoded}x")).is_err());
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

    /// The owner delegation CID production actually mints. Delegations are
    /// blake3-addressed, so they arrive as `bafkr4i`, not the `bafkrei`
    /// (sha2-256) prefix `valid_cid` accepts.
    ///
    /// `ShareDelegationCid` was on `valid_cid` while `NodeDelegationCid` had
    /// already been widened, so `typed_scope` could not parse this value and
    /// every addressed recipient claim on production was refused a flat
    /// `403 policy_denied` (TC-451). Captured from a live claim on 2026-07-31.
    const PRODUCTION_OWNER_DELEGATION_CID: &str =
        "bafkr4iaickipp4ceomv46xkot4ujivcogxhmvf6xiqhqpvuuxz2urxrt7u";

    #[test]
    fn delegation_cids_accept_the_blake3_prefix_production_mints() {
        assert!(ShareDelegationCid::parse(PRODUCTION_OWNER_DELEGATION_CID).is_ok());
        assert!(NodeDelegationCid::parse(PRODUCTION_OWNER_DELEGATION_CID).is_ok());
    }

    #[test]
    fn content_addressed_cids_still_require_sha256() {
        // Share and policy CIDs are content-addressed by this module itself and
        // stay sha2-256 only; widening the delegation validator must not widen
        // these.
        assert!(ShareCid::parse(PRODUCTION_OWNER_DELEGATION_CID).is_err());
        assert!(PolicyCid::parse(PRODUCTION_OWNER_DELEGATION_CID).is_err());
        assert!(ShareCid::parse(KV_SHARE_CID).is_ok());
        assert!(PolicyCid::parse(KV_POLICY_CID).is_ok());
    }

    #[test]
    fn delegation_cids_still_reject_malformed_values() {
        assert!(ShareDelegationCid::parse("bafkr4i").is_err());
        assert!(ShareDelegationCid::parse(format!(
            "zzzzzzz{}",
            &PRODUCTION_OWNER_DELEGATION_CID[7..]
        ))
        .is_err());
        // Wrong length, right prefix.
        assert!(ShareDelegationCid::parse(&PRODUCTION_OWNER_DELEGATION_CID[..58]).is_err());
        // base32 alphabet only: `1` and `8` are not in it.
        assert!(ShareDelegationCid::parse(format!(
            "bafkr4i1{}",
            &PRODUCTION_OWNER_DELEGATION_CID[8..]
        ))
        .is_err());
    }
}
