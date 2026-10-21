//! Admission for a presentation of a held email credential (profile
//! `tinycloud.email-held/v1`, vct `opencredentials.email/v1`).
//!
//! Port of the TypeScript verifier in `held-credentials/` (verify.ts, siwe.ts,
//! encoding.ts, did.ts, crypto.ts, rows.ts). Refusal codes keep the TypeScript
//! names. Verification is two-phase so the nonce is spent before any signature
//! work: `precheck` (no side effects), then the caller consumes the nonce, then
//! `verify`. Only the nonce store touches the database.

use crate::issuer_set::{IssuerSet, IssuerWindowError};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use ed25519_dalek::{Signature, VerifyingKey};
use k256::ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey as EcdsaVerifyingKey};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_core::{
    models::held_credential_nonce,
    sea_orm::{ColumnTrait, DbErr, EntityTrait, QueryFilter},
    RecoveringConnection,
};

/// A refusal code. The string is the wire code; callers map it to a status.
pub type Refusal = &'static str;

pub const PROFILE: &str = "tinycloud.email-held/v1";
pub const PROFILE_VERSION: i64 = 1;
pub const VCT: &str = "opencredentials.email/v1";
const HOLDER_CHAIN: &str = "1";
const BINDING_DOMAIN: &str = "tinycloud.credentials/account-binding/v1";
const MAX_LIFETIME_SECONDS: i64 = 365 * 24 * 60 * 60;
const STATUS_METHODS: &[&str] = &["none"];
const DISCLOSABLE: &[&str] = &["email", "emailDomain"];
// Size caps, as the upstream verifier's HELD_LIMITS.
const MAX_SD_JWT_CHARS: usize = 16384;
const MAX_SIWE_MESSAGE_CHARS: usize = 2048;
const MAX_SIWE_SIGNATURE_CHARS: usize = 132;
const MAX_DISCLOSURES: usize = 8;
const MAX_DISCLOSURE_CHARS: usize = 1024;
const MAX_HEADER_CHARS: usize = 1024;
const MAX_PAYLOAD_CHARS: usize = 4096;
const MAX_SIGNATURE_CHARS: usize = 128;
const HEADER_MEMBERS: &[&str] = &["alg", "typ", "kid"];
const SHARED_SIGNED: &[&str] = &[
    "iss",
    "sub",
    "iat",
    "nbf",
    "exp",
    "jti",
    "vct",
    "profile",
    "profileVersion",
    "holderBinding",
    "status",
    "_sd_alg",
    "_sd",
];
const RESERVED: &[&str] = &[
    "iss",
    "sub",
    "iat",
    "nbf",
    "exp",
    "jti",
    "vct",
    "profile",
    "profileVersion",
    "holderBinding",
    "status",
    "_sd_alg",
    "_sd",
    "...",
    "cnf",
];
const PRESENTATION_STATEMENT: &str = "Present a TinyCloud held credential";
const SD_HASH_PREFIX: &str = "urn:tinycloud:sd-hash:";
/// DID methods a held credential's issuer may use.
const HELD_ISSUER_DID_METHODS: &[&str] = &["web"];
const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

pub(crate) const BAD_CONFIG: Refusal = "bad-config";
/// The authenticated account owner is not a canonical `did:pkh:eip155` account.
/// Refused as a client error (403), unlike `BAD_CONFIG`, which is a server 500.
pub(crate) const ACCOUNT_OWNER_INVALID: Refusal = "account-owner-invalid";
const BAD_PRESENTATION: Refusal = "bad-presentation";
const BAD_HEADER: Refusal = "bad-header";
const DID_METHOD_NOT_ALLOWED: Refusal = "did-method-not-allowed";
const ISSUER_NOT_ACCEPTED: Refusal = "issuer-not-accepted";
const UNKNOWN_ISSUER: Refusal = "unknown-issuer";
const ISSUER_NOT_YET_VALID: Refusal = "issuer-not-yet-valid";
const ISSUER_STOPPED: Refusal = "issuer-stopped";
const ISSUER_RETIRED: Refusal = "issuer-retired";
const BAD_SIGNATURE: Refusal = "bad-signature";
const BAD_PAYLOAD: Refusal = "bad-payload";
const PROFILE_MISMATCH: Refusal = "profile-mismatch";
const PROFILE_NOT_ACCEPTED: Refusal = "profile-not-accepted";
const NOT_YET_VALID: Refusal = "not-yet-valid";
const EXPIRED: Refusal = "expired";
const BAD_LIFETIME: Refusal = "bad-lifetime";
const BAD_STATUS: Refusal = "bad-status";
const BAD_SUBJECT: Refusal = "bad-subject";
const BAD_HOLDER_BINDING: Refusal = "bad-holder-binding";
const BAD_DISCLOSURE: Refusal = "bad-disclosure";
const BAD_SIWE: Refusal = "bad-siwe";
const BAD_SIWE_SIGNATURE: Refusal = "bad-siwe-signature";
const BAD_NONCE: Refusal = "bad-nonce";
const NONCE_ACCOUNT_MISMATCH: Refusal = "nonce-account-mismatch";

/// An issuer the relying party accepts. `kid: None` accepts any key of `did`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedIssuer {
    pub did: String,
    pub kid: Option<String>,
}

/// A profile the relying party accepts, by identifier and version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AcceptedProfile {
    pub id: String,
    pub version: i64,
}

/// Everything the verifier reads from the request and the node, all immutable.
pub struct HeldPolicy<'a> {
    pub now: OffsetDateTime,
    pub audience: &'a str,
    /// The CACAO-authenticated account, as `did:pkh:eip155:…`.
    pub caller_account: &'a str,
    pub accepted_issuers: &'a [AcceptedIssuer],
    pub accepted_profiles: &'a [AcceptedProfile],
    pub issuers: &'a IssuerSet,
}

/// The two parts of a held presentation, as the request carries them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeldPresentation<'a> {
    pub sd_jwt: &'a str,
    pub siwe_message: &'a str,
    pub siwe_signature: &'a str,
}

/// Output of phase A. Holds the parsed SIWE and the nonce to consume.
#[derive(Debug, Clone)]
pub struct Precheck {
    pub nonce: String,
    /// Canonical account key used for the nonce store.
    pub account_key: String,
    account: Pkh,
    siwe: Siwe,
}

/// A credential that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedHeld {
    pub issuer: String,
    pub subject: String,
    pub subject_address: String,
    pub expires_at: i64,
    pub credential_id: String,
    pub profile: String,
    pub profile_version: i64,
    pub vct: String,
    pub claims: BTreeMap<String, String>,
}

/// Reads the `presentation` object: exactly `sdJwt` and `siwe`, and `siwe`
/// holds exactly `message` and `signature`.
pub fn read_presentation(value: &Value) -> Result<HeldPresentation<'_>, Refusal> {
    let object = value.as_object().ok_or(BAD_PRESENTATION)?;
    if object.len() != 2 {
        return Err(BAD_PRESENTATION);
    }
    let sd_jwt = object
        .get("sdJwt")
        .and_then(Value::as_str)
        .ok_or(BAD_PRESENTATION)?;
    let siwe = object
        .get("siwe")
        .and_then(Value::as_object)
        .ok_or(BAD_PRESENTATION)?;
    if siwe.len() != 2 {
        return Err(BAD_PRESENTATION);
    }
    let siwe_message = siwe
        .get("message")
        .and_then(Value::as_str)
        .ok_or(BAD_PRESENTATION)?;
    let siwe_signature = siwe
        .get("signature")
        .and_then(Value::as_str)
        .ok_or(BAD_PRESENTATION)?;
    Ok(HeldPresentation {
        sd_jwt,
        siwe_message,
        siwe_signature,
    })
}

/// Phase A: no side effects. Checks inputs, parses the SIWE, and checks its
/// domain and nonce. The caller consumes `Precheck::nonce` next.
pub fn precheck(
    input: &HeldPresentation<'_>,
    policy: &HeldPolicy<'_>,
) -> Result<Precheck, Refusal> {
    if policy.accepted_issuers.is_empty() || policy.accepted_profiles.is_empty() {
        return Err(BAD_CONFIG);
    }
    if !valid_audience(policy.audience) {
        return Err(BAD_CONFIG);
    }
    let account = parse_pkh(policy.caller_account).ok_or(ACCOUNT_OWNER_INVALID)?;
    if !input.sd_jwt.is_ascii() {
        return Err(BAD_PRESENTATION);
    }
    if input.sd_jwt.len() > MAX_SD_JWT_CHARS
        || input.siwe_message.len() > MAX_SIWE_MESSAGE_CHARS
        || input.siwe_signature.len() > MAX_SIWE_SIGNATURE_CHARS
    {
        return Err(BAD_PRESENTATION);
    }
    let siwe = parse_siwe(input.siwe_message)?;
    if siwe.domain != policy.audience {
        return Err(BAD_SIWE);
    }
    if !valid_nonce(&siwe.nonce) {
        return Err(BAD_NONCE);
    }
    Ok(Precheck {
        nonce: siwe.nonce.clone(),
        account_key: account.canonical(),
        account,
        siwe,
    })
}

/// Phase B: every remaining check, in refusal order. Runs after the nonce is
/// consumed, so a refusal here leaves the nonce spent.
pub fn verify(
    input: &HeldPresentation<'_>,
    pre: &Precheck,
    policy: &HeldPolicy<'_>,
) -> Result<VerifiedHeld, Refusal> {
    // Split the SD-JWT: `jwt~disclosure…~`, with a trailing empty part.
    let parts: Vec<&str> = input.sd_jwt.split('~').collect();
    if parts.len() < 2 || !parts[parts.len() - 1].is_empty() {
        return Err(BAD_PRESENTATION);
    }
    let disclosures = &parts[1..parts.len() - 1];
    if disclosures.iter().any(|part| part.is_empty()) {
        return Err(BAD_PRESENTATION);
    }
    let segments: Vec<&str> = parts[0].split('.').collect();
    if segments.len() != 3 || segments.iter().any(|segment| segment.is_empty()) {
        return Err(BAD_PRESENTATION);
    }
    if disclosures.len() > MAX_DISCLOSURES
        || disclosures
            .iter()
            .any(|part| part.len() > MAX_DISCLOSURE_CHARS)
        || segments[0].len() > MAX_HEADER_CHARS
        || segments[1].len() > MAX_PAYLOAD_CHARS
        || segments[2].len() > MAX_SIGNATURE_CHARS
    {
        return Err(BAD_PRESENTATION);
    }

    // Protected header.
    let header = decode_object(segments[0], BAD_HEADER)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA")
        || header.get("typ").and_then(Value::as_str) != Some("vc+sd-jwt")
    {
        return Err(BAD_HEADER);
    }
    if header
        .keys()
        .any(|key| !HEADER_MEMBERS.contains(&key.as_str()))
    {
        return Err(BAD_HEADER);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(BAD_HEADER)?;
    let hash = kid
        .find('#')
        .filter(|&index| index >= 1)
        .ok_or(BAD_HEADER)?;
    let issuer_did = &kid[..hash];
    if !is_kid_fragment(&kid[hash + 1..]) {
        return Err(BAD_HEADER);
    }
    let method = did_method(issuer_did).ok_or(DID_METHOD_NOT_ALLOWED)?;
    if !HELD_ISSUER_DID_METHODS.contains(&method) {
        return Err(DID_METHOD_NOT_ALLOWED);
    }

    // Policy: the requirement must accept this issuer, and the pinned set must hold it.
    let issuer_accepted = policy.accepted_issuers.iter().any(|accepted| {
        accepted.did == issuer_did
            && accepted
                .kid
                .as_deref()
                .is_none_or(|required| required == kid)
    });
    if !issuer_accepted {
        return Err(ISSUER_NOT_ACCEPTED);
    }
    let entry = policy
        .issuers
        .resolve_pinned_issuer(issuer_did, kid)
        .ok_or(UNKNOWN_ISSUER)?;
    entry.check_now(policy.now).map_err(window_refusal)?;

    // Signature over `header.payload` with the pinned key, strictly.
    let signature_bytes = b64url_strict(segments[2]).ok_or(BAD_SIGNATURE)?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| BAD_SIGNATURE)?;
    let key = VerifyingKey::from_bytes(&entry.public_key).map_err(|_| BAD_SIGNATURE)?;
    let signing_input = format!("{}.{}", segments[0], segments[1]);
    key.verify_strict(signing_input.as_bytes(), &signature)
        .map_err(|_| BAD_SIGNATURE)?;

    // Payload.
    let payload = decode_object(segments[1], BAD_PAYLOAD)?;
    if payload.get("iss").and_then(Value::as_str) != Some(issuer_did) {
        return Err(BAD_PAYLOAD);
    }
    let iat = safe_int(payload.get("iat")).ok_or(BAD_PAYLOAD)?;
    let exp = safe_int(payload.get("exp")).ok_or(BAD_PAYLOAD)?;
    let nbf = safe_int(payload.get("nbf")).ok_or(BAD_PAYLOAD)?;
    if nbf != iat {
        return Err(BAD_PAYLOAD);
    }
    // Clamp into the representable range. Every configured instant lies inside it, so the
    // window comparisons are unchanged; `nbf` is compared as an integer below.
    let issued_at = OffsetDateTime::from_unix_timestamp(iat.clamp(
        OffsetDateTime::new_utc(time::Date::MIN, time::Time::MIDNIGHT).unix_timestamp(),
        OffsetDateTime::new_utc(time::Date::MAX, time::Time::MAX).unix_timestamp(),
    ))
    .map_err(|_| BAD_PAYLOAD)?;
    entry.check_issued_at(issued_at).map_err(window_refusal)?;

    let profile = payload
        .get("profile")
        .and_then(Value::as_str)
        .ok_or(BAD_PAYLOAD)?;
    let profile_version = safe_int(payload.get("profileVersion")).ok_or(BAD_PAYLOAD)?;
    let vct = payload
        .get("vct")
        .and_then(Value::as_str)
        .ok_or(BAD_PAYLOAD)?;
    if profile != PROFILE || profile_version != PROFILE_VERSION {
        return Err(PROFILE_MISMATCH);
    }
    let profile_accepted = policy
        .accepted_profiles
        .iter()
        .any(|accepted| accepted.id == PROFILE && accepted.version == PROFILE_VERSION);
    if !profile_accepted {
        return Err(PROFILE_NOT_ACCEPTED);
    }
    if vct != VCT || !entry.admits(vct, profile) {
        return Err(PROFILE_MISMATCH);
    }

    for key in payload.keys() {
        let name = key.as_str();
        if !SHARED_SIGNED.contains(&name) {
            return Err(BAD_PAYLOAD);
        }
    }
    if payload.get("_sd_alg").and_then(Value::as_str) != Some("sha-256") {
        return Err(BAD_PAYLOAD);
    }
    let sd_digests: Vec<&str> = payload
        .get("_sd")
        .and_then(Value::as_array)
        .and_then(|digests| {
            digests
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<&str>>>()
        })
        .ok_or(BAD_PAYLOAD)?;
    let distinct: BTreeSet<&str> = sd_digests.iter().copied().collect();
    if distinct.len() != sd_digests.len() {
        return Err(BAD_PAYLOAD);
    }

    let now = policy.now.unix_timestamp();
    if now < nbf {
        return Err(NOT_YET_VALID);
    }
    if now >= exp {
        return Err(EXPIRED);
    }
    let lifetime = exp - iat;
    if lifetime <= 0 || lifetime > MAX_LIFETIME_SECONDS {
        return Err(BAD_LIFETIME);
    }
    let jti = payload
        .get("jti")
        .and_then(Value::as_str)
        .filter(|value| is_uuid_v4_urn(value))
        .ok_or(BAD_PAYLOAD)?;
    let status = payload
        .get("status")
        .and_then(Value::as_object)
        .ok_or(BAD_STATUS)?;
    let status_method = status.get("method").and_then(Value::as_str);
    if status.len() != 1 || !status_method.is_some_and(|m| STATUS_METHODS.contains(&m)) {
        return Err(BAD_STATUS);
    }

    let sub = payload
        .get("sub")
        .and_then(Value::as_str)
        .ok_or(BAD_SUBJECT)?;
    let subject = parse_pkh(sub)
        .filter(|did| did.chain == HOLDER_CHAIN)
        .ok_or(BAD_SUBJECT)?;

    let binding = payload
        .get("holderBinding")
        .and_then(Value::as_object)
        .ok_or(BAD_HOLDER_BINDING)?;
    if binding.len() != 2
        || binding.get("signingDomain").and_then(Value::as_str) != Some(BINDING_DOMAIN)
    {
        return Err(BAD_HOLDER_BINDING);
    }
    let binding_did = binding
        .get("did")
        .and_then(Value::as_str)
        .and_then(parse_pkh)
        .ok_or(BAD_HOLDER_BINDING)?;
    if binding_did != subject {
        return Err(BAD_HOLDER_BINDING);
    }

    // Disclosures: each must hash into `_sd`, appear once, and name a disclosable claim.
    let mut seen_digests = BTreeSet::new();
    let mut seen_names = BTreeSet::new();
    let mut claims = BTreeMap::new();
    for disclosure in disclosures {
        let digest = b64url(&sha256(disclosure.as_bytes()));
        if !sd_digests.contains(&digest.as_str()) || !seen_digests.insert(digest) {
            return Err(BAD_DISCLOSURE);
        }
        let decoded = b64url_strict(disclosure).ok_or(BAD_DISCLOSURE)?;
        let array = match strict_json(std::str::from_utf8(&decoded).map_err(|_| BAD_DISCLOSURE)?) {
            Some(Value::Array(items)) if items.len() == 3 => items,
            _ => return Err(BAD_DISCLOSURE),
        };
        let salt_ok = array[0].as_str().is_some();
        let name = array[1].as_str().ok_or(BAD_DISCLOSURE)?;
        let value = array[2].as_str().ok_or(BAD_DISCLOSURE)?;
        if !salt_ok
            || RESERVED.contains(&name)
            || !DISCLOSABLE.contains(&name)
            || !seen_names.insert(name.to_owned())
        {
            return Err(BAD_DISCLOSURE);
        }
        claims.insert(name.to_owned(), value.to_owned());
    }
    validate_disclosed(&claims)?;

    // SIWE against the credential.
    let siwe = &pre.siwe;
    if !uri_matches_audience(&siwe.uri, policy.audience)
        || siwe.version != "1"
        || siwe.statement != PRESENTATION_STATEMENT
        || siwe.chain_id != HOLDER_CHAIN
        || siwe.address.to_ascii_lowercase() != subject.address
        || siwe.resources.len() != 1
    {
        return Err(BAD_SIWE);
    }
    let expected_resource = format!(
        "{SD_HASH_PREFIX}{}",
        b64url(&sha256(input.sd_jwt.as_bytes()))
    );
    if siwe.resources[0] != expected_resource {
        return Err(BAD_SIWE);
    }
    let now = truncate_to_millis(policy.now);
    let expired = siwe
        .expiration
        .is_some_and(|expiry| now >= truncate_to_millis(expiry));
    let early = siwe
        .not_before
        .is_some_and(|start| now < truncate_to_millis(start));
    if expired || early {
        return Err(BAD_SIWE);
    }
    let signature_hex = input
        .siwe_signature
        .strip_prefix("0x")
        .ok_or(BAD_SIWE_SIGNATURE)?;
    let siwe_signature = hex::decode(signature_hex)
        .ok()
        .filter(|bytes| bytes.len() == 65)
        .ok_or(BAD_SIWE_SIGNATURE)?;
    let signer = recover_eip191_address(input.siwe_message.as_bytes(), &siwe_signature)
        .ok_or(BAD_SIWE_SIGNATURE)?;
    if signer != subject.address {
        return Err(BAD_SIWE_SIGNATURE);
    }

    // The signed-in account must be the holder.
    if pre.account != subject {
        return Err(NONCE_ACCOUNT_MISMATCH);
    }

    Ok(VerifiedHeld {
        issuer: issuer_did.to_owned(),
        subject: subject.display_did(),
        subject_address: subject.address,
        expires_at: exp,
        credential_id: jti.to_owned(),
        profile: profile.to_owned(),
        profile_version,
        vct: vct.to_owned(),
        claims,
    })
}

/// Consumes a nonce bound to `(audience, account)` that is still live at `now`.
/// A nonce is live while `now < expires_at`. Returns `false` if it was not
/// outstanding, so the caller refuses with `nonce-replayed`. A mismatched
/// account or an expired nonce matches no row and spends nothing. Rows already
/// expired are pruned on every call, so the table holds only live nonces.
pub async fn consume_nonce(
    conn: &RecoveringConnection,
    audience: &str,
    nonce: &str,
    account_key: &str,
    now: OffsetDateTime,
) -> Result<bool, DbErr> {
    let now = now.unix_timestamp();
    held_credential_nonce::Entity::delete_many()
        .filter(held_credential_nonce::Column::ExpiresAt.lte(now))
        .exec(conn)
        .await?;
    let deleted = held_credential_nonce::Entity::delete_many()
        .filter(held_credential_nonce::Column::Audience.eq(audience))
        .filter(held_credential_nonce::Column::Nonce.eq(nonce))
        .filter(held_credential_nonce::Column::Account.eq(account_key))
        .filter(held_credential_nonce::Column::ExpiresAt.gt(now))
        .exec(conn)
        .await?;
    Ok(deleted.rows_affected == 1)
}

/// Records an outstanding nonce that stops being spendable at `expires_at`
/// (unix seconds). Used only by tests until the mint slice lands.
#[cfg(test)]
pub async fn record_nonce(
    conn: &RecoveringConnection,
    audience: &str,
    nonce: &str,
    account_key: &str,
    expires_at: i64,
) -> Result<(), DbErr> {
    use tinycloud_core::sea_orm::{ActiveModelTrait, Set};
    held_credential_nonce::ActiveModel {
        audience: Set(audience.to_owned()),
        nonce: Set(nonce.to_owned()),
        account: Set(account_key.to_owned()),
        expires_at: Set(expires_at),
    }
    .insert(conn)
    .await?;
    Ok(())
}

fn window_refusal(error: IssuerWindowError) -> Refusal {
    match error {
        IssuerWindowError::NotYetValid => ISSUER_NOT_YET_VALID,
        IssuerWindowError::Stopped => ISSUER_STOPPED,
        IssuerWindowError::Retired => ISSUER_RETIRED,
    }
}

/// Decodes a base64url JSON object, refusing duplicate keys at every depth.
fn decode_object(segment: &str, refusal: Refusal) -> Result<Map<String, Value>, Refusal> {
    let bytes = b64url_strict(segment).ok_or(refusal)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| refusal)?;
    match strict_json(text) {
        Some(Value::Object(object)) => Ok(object),
        _ => Err(refusal),
    }
}

/// A JSON value parsed with duplicate keys refused at any depth.
struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictJson;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a JSON value")
            }

            fn visit_bool<E>(self, value: bool) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }

            fn visit_u64<E>(self, value: u64) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::from(value)))
            }

            fn visit_f64<E: de::Error>(self, value: f64) -> Result<StrictJson, E> {
                serde_json::Number::from_f64(value)
                    .map(|number| StrictJson(Value::Number(number)))
                    .ok_or_else(|| E::custom("non-finite number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::String(value)))
            }

            fn visit_unit<E>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_none<E>(self) -> Result<StrictJson, E> {
                Ok(StrictJson(Value::Null))
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<StrictJson, A::Error> {
                let mut items = Vec::new();
                while let Some(StrictJson(item)) = seq.next_element()? {
                    items.push(item);
                }
                Ok(StrictJson(Value::Array(items)))
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<StrictJson, A::Error> {
                let mut object = Map::new();
                while let Some(key) = map.next_key::<String>()? {
                    if object.contains_key(&key) {
                        return Err(de::Error::custom("duplicate key"));
                    }
                    let StrictJson(value) = map.next_value()?;
                    object.insert(key, value);
                }
                Ok(StrictJson(Value::Object(object)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn strict_json(text: &str) -> Option<Value> {
    serde_json::from_str::<StrictJson>(text)
        .ok()
        .map(|StrictJson(value)| value)
}

/// An integer literal within the JSON-safe range. `1.0` is refused.
fn safe_int(value: Option<&Value>) -> Option<i64> {
    let number = value?.as_number()?.as_i64()?;
    (number.abs() <= MAX_SAFE_INTEGER).then_some(number)
}

/// Unpadded base64url, canonical: no foreign characters, no stray trailing bits.
fn b64url_strict(text: &str) -> Option<Vec<u8>> {
    if text.len() % 4 == 1
        || !text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return None;
    }
    let bytes = decode_config(text, URL_SAFE_NO_PAD).ok()?;
    (encode_config(&bytes, URL_SAFE_NO_PAD) == text).then_some(bytes)
}

fn b64url(bytes: &[u8]) -> String {
    encode_config(bytes, URL_SAFE_NO_PAD)
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn keccak(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

fn is_kid_fragment(fragment: &str) -> bool {
    !fragment.is_empty()
        && fragment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// The method of a `did:<method>:<id>` string, using the `did:[a-z0-9]+:` grammar. The id
/// is not checked here; an empty id is refused later as an unaccepted issuer.
fn did_method(did: &str) -> Option<&str> {
    let mut parts = did.splitn(3, ':');
    if parts.next()? != "did" {
        return None;
    }
    let method = parts.next()?;
    parts.next()?;
    (!method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()))
    .then_some(method)
}

/// A `did:pkh:eip155` principal. `address` is lowercase `0x…`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Pkh {
    chain: String,
    address: String,
}

impl Pkh {
    fn canonical(&self) -> String {
        format!("did:pkh:eip155:{}:{}", self.chain, self.address)
    }

    /// The `did:pkh` with the EIP-55 checksummed address, as TS `canonicalPkhDid`.
    fn display_did(&self) -> String {
        format!(
            "did:pkh:eip155:{}:{}",
            self.chain,
            checksum_address(&self.address)
        )
    }
}

/// Parses `did:pkh:eip155:<chain>:<address>`. Chain is `0` or a decimal with no
/// leading zero, up to 16 digits. The address must be all-lowercase or valid EIP-55.
fn parse_pkh(did: &str) -> Option<Pkh> {
    let rest = did.strip_prefix("did:pkh:eip155:")?;
    let (chain, address) = rest.split_once(':')?;
    let chain_ok = !chain.is_empty()
        && chain.bytes().all(|b| b.is_ascii_digit())
        && (chain == "0" || (!chain.starts_with('0') && chain.len() <= 16));
    if !chain_ok || address.len() != 42 || !address.starts_with("0x") {
        return None;
    }
    let hex_part = &address[2..];
    hex::decode(hex_part).ok()?;
    // TS `parsePkhDid`: an all-lowercase body is accepted; any other body must be EIP-55.
    if hex_part != hex_part.to_ascii_lowercase() && !eip55_ok(hex_part) {
        return None;
    }
    Some(Pkh {
        chain: chain.to_owned(),
        address: address.to_ascii_lowercase(),
    })
}

/// EIP-55 checksum of a `0x…` address, as `toChecksumAddress`.
fn checksum_address(address: &str) -> String {
    let lower = address[2..].to_ascii_lowercase();
    let digest = keccak(lower.as_bytes());
    let body: String = lower
        .char_indices()
        .map(|(index, c)| {
            let nibble = if index % 2 == 0 {
                digest[index / 2] >> 4
            } else {
                digest[index / 2] & 0x0f
            };
            if c.is_ascii_alphabetic() && nibble >= 8 {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect();
    format!("0x{body}")
}

/// EIP-55: each letter's case must match the keccak-derived checksum, which is
/// `toChecksumAddress(address) === address`. All-lower and all-upper spellings
/// pass only when the checksum happens to agree with them.
fn eip55_ok(hex40: &str) -> bool {
    checksum_address(&format!("0x{}", hex40.to_ascii_lowercase())) == format!("0x{hex40}")
}

/// EIP-191 `personal_sign` recovery over the raw message bytes. Accepts v in
/// {27, 28, 0, 1}. High-S is refused: `recover_from_prehash` verifies the
/// signature with `verify_prehash`, which enforces low-S. TS beta.37 recovers
/// high-S signatures (no low-S check); that divergence is tracked on TC-1540.
fn recover_eip191_address(message: &[u8], signature: &[u8]) -> Option<String> {
    let mut prefixed = format!("\x19Ethereum Signed Message:\n{}", message.len()).into_bytes();
    prefixed.extend_from_slice(message);
    let digest = keccak(&prefixed);
    let v = match signature[64] {
        27 | 28 => signature[64] - 27,
        0 | 1 => signature[64],
        _ => return None,
    };
    let recovery_id = RecoveryId::from_byte(v)?;
    let rs = EcdsaSignature::from_slice(&signature[..64]).ok()?;
    let key = EcdsaVerifyingKey::recover_from_prehash(&digest, &rs, recovery_id).ok()?;
    let point = key.to_encoded_point(false);
    let hash = keccak(&point.as_bytes()[1..]);
    Some(format!("0x{}", hex::encode(&hash[12..])))
}

/// Audience: a lowercase host with an optional port in `1..=65535`, not 443.
pub(crate) fn valid_audience(audience: &str) -> bool {
    let (host, port) = match audience.rsplit_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (audience, None),
    };
    let is_edge = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit();
    let host_ok = !host.is_empty()
        && host.bytes().all(|b| is_edge(b) || b == b'.' || b == b'-')
        && host.bytes().next().is_some_and(is_edge)
        && host.bytes().last().is_some_and(is_edge);
    let port_ok = match port {
        None => true,
        Some(port) => {
            port.len() <= 5
                && !port.starts_with('0')
                && port.bytes().all(|b| b.is_ascii_digit())
                && port
                    .parse::<u32>()
                    .is_ok_and(|value| value <= 65535 && value != 443)
        }
    };
    host_ok && port_ok
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() >= 22 && nonce.bytes().all(|b| b.is_ascii_alphanumeric())
}

/// `urn:uuid:` plus a lowercase RFC 4122 version-4 UUID: the upstream
/// JTI_UUID_V4 pattern.
fn is_uuid_v4_urn(value: &str) -> bool {
    let Some(uuid) = value.strip_prefix("urn:uuid:") else {
        return false;
    };
    uuid.len() == 36
        && uuid.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'4',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

fn is_eth_address(line: &str) -> bool {
    line.len() == 42
        && line.starts_with("0x")
        && hex::decode(&line[2..]).is_ok()
        && eip55_ok(&line[2..])
}

/// A parsed EIP-4361 message, strictly. Only the fields the verifier reads.
#[derive(Debug, Clone)]
struct Siwe {
    domain: String,
    address: String,
    statement: String,
    uri: String,
    version: String,
    chain_id: String,
    nonce: String,
    expiration: Option<OffsetDateTime>,
    not_before: Option<OffsetDateTime>,
    resources: Vec<String>,
}

const SIWE_HEADER_SUFFIX: &str = " wants you to sign in with your Ethereum account:";

fn parse_siwe(message: &str) -> Result<Siwe, Refusal> {
    let lines: Vec<&str> = message.split('\n').collect();
    let domain = lines
        .first()
        .and_then(|line| line.strip_suffix(SIWE_HEADER_SUFFIX))
        .filter(|domain| !domain.is_empty() && !domain.bytes().any(|b| b.is_ascii_whitespace()))
        .ok_or(BAD_SIWE)?;
    let address = lines
        .get(1)
        .copied()
        .filter(|line| is_eth_address(line))
        .ok_or(BAD_SIWE)?;
    if lines.get(2) != Some(&"") {
        return Err(BAD_SIWE);
    }
    let statement = lines
        .get(3)
        .copied()
        .filter(|line| !line.is_empty())
        .ok_or(BAD_SIWE)?;
    if lines.get(4) != Some(&"") {
        return Err(BAD_SIWE);
    }
    let mut index = 5;
    let uri = take_field(&lines, &mut index, "URI: ")?;
    let version = take_field(&lines, &mut index, "Version: ")?;
    let chain_id = take_field(&lines, &mut index, "Chain ID: ")?;
    let nonce = take_field(&lines, &mut index, "Nonce: ")?;
    let issued_at = take_field(&lines, &mut index, "Issued At: ")?;
    let expiration = take_optional(&lines, &mut index, "Expiration Time: ")?;
    let not_before = take_optional(&lines, &mut index, "Not Before: ")?;
    let mut resources = Vec::new();
    if lines.get(index) == Some(&"Resources:") {
        index += 1;
        while let Some(item) = lines.get(index).and_then(|line| line.strip_prefix("- ")) {
            if item.is_empty() {
                return Err(BAD_SIWE);
            }
            resources.push(item.to_owned());
            index += 1;
        }
    }
    if index != lines.len() {
        return Err(BAD_SIWE);
    }
    if !chain_id.bytes().all(|b| b.is_ascii_digit())
        || nonce.len() < 8
        || !nonce.bytes().all(|b| b.is_ascii_alphanumeric())
    {
        return Err(BAD_SIWE);
    }
    parse_rfc3339(issued_at)?;
    Ok(Siwe {
        domain: domain.to_owned(),
        address: address.to_owned(),
        statement: statement.to_owned(),
        uri: uri.to_owned(),
        version: version.to_owned(),
        chain_id: chain_id.to_owned(),
        nonce: nonce.to_owned(),
        expiration: expiration.map(parse_rfc3339).transpose()?,
        not_before: not_before.map(parse_rfc3339).transpose()?,
        resources,
    })
}

fn take_field<'a>(lines: &[&'a str], index: &mut usize, prefix: &str) -> Result<&'a str, Refusal> {
    let value = lines
        .get(*index)
        .and_then(|line| line.strip_prefix(prefix))
        .filter(|value| !value.is_empty())
        .ok_or(BAD_SIWE)?;
    *index += 1;
    Ok(value)
}

fn take_optional<'a>(
    lines: &[&'a str],
    index: &mut usize,
    prefix: &str,
) -> Result<Option<&'a str>, Refusal> {
    if lines
        .get(*index)
        .is_some_and(|line| line.starts_with(prefix))
    {
        Ok(Some(take_field(lines, index, prefix)?))
    } else {
        Ok(None)
    }
}

/// RFC 3339 with the exact shape `YYYY-MM-DDTHH:MM:SS[.frac](Z|±HH:MM)`.
fn parse_rfc3339(text: &str) -> Result<OffsetDateTime, Refusal> {
    if !rfc3339_shape(text) {
        return Err(BAD_SIWE);
    }
    OffsetDateTime::parse(text, &Rfc3339).map_err(|_| BAD_SIWE)
}

/// TS compares SIWE times as JavaScript `Date` values, which keep milliseconds only.
fn truncate_to_millis(time: OffsetDateTime) -> OffsetDateTime {
    let nanos = time.nanosecond() - time.nanosecond() % 1_000_000;
    time.replace_nanosecond(nanos).unwrap_or(time)
}

fn rfc3339_shape(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |from: usize, len: usize| {
        bytes.len() >= from + len && bytes[from..from + len].iter().all(u8::is_ascii_digit)
    };
    let separators_ok = bytes.get(4) == Some(&b'-')
        && bytes.get(7) == Some(&b'-')
        && bytes.get(10) == Some(&b'T')
        && bytes.get(13) == Some(&b':')
        && bytes.get(16) == Some(&b':');
    if !(separators_ok
        && digits(0, 4)
        && digits(5, 2)
        && digits(8, 2)
        && digits(11, 2)
        && digits(14, 2)
        && digits(17, 2)
        && bytes[17] <= b'5')
    {
        return false;
    }
    let mut index = 19;
    if bytes.get(index) == Some(&b'.') {
        index += 1;
        let start = index;
        while bytes.get(index).is_some_and(u8::is_ascii_digit) {
            index += 1;
        }
        if index == start {
            return false;
        }
        if index - start > 9 {
            return false;
        }
    }
    let tail = &bytes[index..];
    if tail == b"Z" {
        return true;
    }
    tail.len() == 6
        && (tail[0] == b'+' || tail[0] == b'-')
        && tail[1..3].iter().all(u8::is_ascii_digit)
        && tail[3] == b':'
        && tail[4..6].iter().all(u8::is_ascii_digit)
}

/// The SIWE URI: https, no userinfo, and its origin (host, plus the port when it is
/// not the https default) equals the audience, as WHATWG `URL.origin` does.
fn uri_matches_audience(uri: &str, audience: &str) -> bool {
    let Ok(parsed) = url::Url::parse(uri) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let origin = match parsed.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_owned(),
    };
    parsed.scheme() == "https"
        && parsed.username().is_empty()
        && parsed.password().is_none()
        && origin == audience
}

/// Checks the disclosed values against the email row's rules.
fn validate_disclosed(claims: &BTreeMap<String, String>) -> Result<(), Refusal> {
    if let Some(email) = claims.get("email") {
        let ok = email.is_ascii()
            && email == &email.to_ascii_lowercase()
            && email.matches('@').count() == 1
            && (3..=320).contains(&email.len())
            && email.bytes().all(|b| b > 0x20 && b != 0x7f)
            && !email.starts_with('@')
            && !email.ends_with('@');
        if !ok {
            return Err(BAD_DISCLOSURE);
        }
    }
    if let Some(domain) = claims.get("emailDomain") {
        if domain.is_empty()
            || domain.contains('@')
            || !domain.is_ascii()
            || domain != &domain.to_ascii_lowercase()
        {
            return Err(BAD_DISCLOSURE);
        }
    }
    if let (Some(email), Some(domain)) = (claims.get("email"), claims.get("emailDomain")) {
        if email.rsplit('@').next() != Some(domain.as_str()) {
            return Err(BAD_DISCLOSURE);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::HeldCredentialsConfig;
    use crate::issuer_set::CredentialIssuerConfig;
    use crate::policy_v3::{
        canonical_digest_base64url, validate_held_email_admission, ClaimPresentationContext,
        PolicyV3Runtime,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;
    use tinycloud_auth::share_email_evidence::IssuerKey;
    use tinycloud_core::keys::StaticSecret;
    use tinycloud_core::migrations::Migrator;
    use tinycloud_core::sea_orm::Database;
    use tinycloud_core::sea_orm_migration::MigratorTrait;

    const AUDIENCE: &str = "verifier.example";
    const HOLDER: &str = "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const CALLER: &str = "did:pkh:eip155:1:0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266";
    const OTHER_ACCOUNT: &str = "did:pkh:eip155:1:0x1111111111111111111111111111111111111111";
    const ANVIL_KEY: &str = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    const TEST_ISSUER: &str = "did:web:issuer.credentials.org";
    const TEST_KID: &str = "did:web:issuer.credentials.org#k1";
    const ISSUED_AT: &str = "2026-01-01T00:59:00Z";
    const NOW: &str = "2026-01-01T01:00:00Z";
    const IAT: i64 = 1_767_225_600;
    const DAY: i64 = 86_400;
    const NONCE: &str = "heldtestnonce0000000001";

    struct Fixture {
        set: IssuerSet,
        issuers: Vec<AcceptedIssuer>,
        profiles: Vec<AcceptedProfile>,
        now: OffsetDateTime,
        caller: String,
    }

    impl Fixture {
        fn new(set: IssuerSet, issuer_did: &str) -> Self {
            Self {
                set,
                issuers: vec![AcceptedIssuer {
                    did: issuer_did.to_owned(),
                    kid: None,
                }],
                profiles: vec![AcceptedProfile {
                    id: PROFILE.to_owned(),
                    version: PROFILE_VERSION,
                }],
                now: OffsetDateTime::parse(NOW, &Rfc3339).unwrap(),
                caller: CALLER.to_owned(),
            }
        }

        fn policy(&self) -> HeldPolicy<'_> {
            HeldPolicy {
                now: self.now,
                audience: AUDIENCE,
                caller_account: &self.caller,
                accepted_issuers: &self.issuers,
                accepted_profiles: &self.profiles,
                issuers: &self.set,
            }
        }
    }

    fn oc_vector() -> Value {
        serde_json::from_str(include_str!("../tests/fixtures/held-email-v1/vector.json")).unwrap()
    }

    /// OC fixture as an admission case: fixture policy plus the SD-JWT and a SIWE message
    /// signed by the subject's account bound to the SD-JWT.
    fn oc_case(nonce: &str) -> (Fixture, String, String) {
        let vector = oc_vector();
        let configured: Vec<CredentialIssuerConfig> =
            serde_json::from_value(vector["issuerSet"]["issuers"].clone()).unwrap();
        let set = IssuerSet::load(&configured).unwrap();
        let mut fixture = Fixture::new(set, "did:web:issuer.credentials.org");
        fixture.now = OffsetDateTime::parse(vector["now"].as_str().unwrap(), &Rfc3339).unwrap();
        fixture.caller = vector["account"].as_str().unwrap().to_owned();
        let sd_jwt = vector["sdJwt"].as_str().unwrap().to_owned();
        let message = siwe_message(nonce, &sd_jwt);
        (fixture, sd_jwt, message)
    }

    fn test_key() -> SigningKey {
        let mut seed = [0u8; 32];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        SigningKey::from_bytes(&seed)
    }

    fn issuer_config(key: &SigningKey) -> CredentialIssuerConfig {
        CredentialIssuerConfig {
            issuer_did: TEST_ISSUER.to_owned(),
            kid: TEST_KID.to_owned(),
            alg: "EdDSA".to_owned(),
            public_key: b64url(&key.verifying_key().to_bytes()),
            vcts: vec![VCT.to_owned()],
            profiles: vec![PROFILE.to_owned()],
            not_before: "2025-01-01T00:00:00Z".to_owned(),
            retired_at: None,
            not_after: None,
        }
    }

    fn own_fixture(key: &SigningKey) -> Fixture {
        Fixture::new(IssuerSet::load(&[issuer_config(key)]).unwrap(), TEST_ISSUER)
    }

    fn disclosure(salt: &str, name: &str, value: &str) -> String {
        b64url(json!([salt, name, value]).to_string().as_bytes())
    }

    fn digest(disclosure: &str) -> String {
        b64url(&sha256(disclosure.as_bytes()))
    }

    fn email_disclosures() -> Vec<String> {
        vec![
            disclosure("salt-email", "email", "alice@example.com"),
            disclosure("salt-domain", "emailDomain", "example.com"),
        ]
    }

    fn default_header() -> Value {
        json!({"alg": "EdDSA", "typ": "vc+sd-jwt", "kid": TEST_KID})
    }

    fn default_payload(disclosures: &[String]) -> Value {
        json!({
            "iss": TEST_ISSUER,
            "sub": CALLER,
            "iat": IAT,
            "nbf": IAT,
            "exp": IAT + 30 * DAY,
            "jti": "urn:uuid:0b6d2c4e-8a1f-4d3e-9b7a-1c2d3e4f5a6b",
            "vct": VCT,
            "profile": PROFILE,
            "profileVersion": PROFILE_VERSION,
            "holderBinding": {
                "did": CALLER,
                "signingDomain": "tinycloud.credentials/account-binding/v1"
            },
            "status": {"method": "none"},
            "_sd_alg": "sha-256",
            "_sd": disclosures.iter().map(|d| digest(d)).collect::<Vec<_>>(),
        })
    }

    fn signing_input(header: &str, payload: &str) -> String {
        format!(
            "{}.{}",
            b64url(header.as_bytes()),
            b64url(payload.as_bytes())
        )
    }

    fn assemble(signing_input: &str, signature: &[u8], disclosures: &[String]) -> String {
        let mut sd_jwt = format!("{signing_input}.{}~", b64url(signature));
        for disclosure in disclosures {
            sd_jwt.push_str(disclosure);
            sd_jwt.push('~');
        }
        sd_jwt
    }

    fn mint(key: &SigningKey, header: &str, payload: &str, disclosures: &[String]) -> String {
        let input = signing_input(header, payload);
        let signature = key.sign(input.as_bytes()).to_bytes();
        assemble(&input, &signature, disclosures)
    }

    /// Honest credential with both email disclosures; `mutate` edits the payload before signing.
    fn credential(key: &SigningKey, header: Value, mutate: impl FnOnce(&mut Value)) -> String {
        let disclosures = email_disclosures();
        let mut payload = default_payload(&disclosures);
        mutate(&mut payload);
        mint(key, &header.to_string(), &payload.to_string(), &disclosures)
    }

    fn sign_siwe(message: &str) -> String {
        sign_siwe_with(ANVIL_KEY, message)
    }

    fn sign_siwe_with(key_hex: &str, message: &str) -> String {
        let prefixed = format!("\x19Ethereum Signed Message:\n{}{}", message.len(), message);
        let digest = keccak(prefixed.as_bytes());
        let key = k256::ecdsa::SigningKey::from_slice(&hex::decode(key_hex).unwrap()).unwrap();
        let (signature, recovery) = key.sign_prehash_recoverable(&digest).unwrap();
        let mut bytes = signature.to_bytes().to_vec();
        bytes.push(recovery.to_byte() + 27);
        format!("0x{}", hex::encode(bytes))
    }

    fn siwe_message(nonce: &str, sd_jwt: &str) -> String {
        [
            format!("{AUDIENCE} wants you to sign in with your Ethereum account:"),
            HOLDER.to_owned(),
            String::new(),
            PRESENTATION_STATEMENT.to_owned(),
            String::new(),
            format!("URI: https://{AUDIENCE}"),
            "Version: 1".to_owned(),
            "Chain ID: 1".to_owned(),
            format!("Nonce: {nonce}"),
            format!("Issued At: {ISSUED_AT}"),
            "Resources:".to_owned(),
            format!(
                "- urn:tinycloud:sd-hash:{}",
                b64url(&sha256(sd_jwt.as_bytes()))
            ),
        ]
        .join("\n")
    }

    fn body(sd_jwt: &str, message: &str, signature: &str) -> Value {
        json!({"sdJwt": sd_jwt, "siwe": {"message": message, "signature": signature}})
    }

    /// Presentation signed with the Anvil test key over a SIWE message bound to `sd_jwt`.
    fn request_for(sd_jwt: &str) -> Value {
        let message = siwe_message(NONCE, sd_jwt);
        body(sd_jwt, &message, &sign_siwe(&message))
    }

    /// Handler order: precheck, consume nonce, then verify.
    async fn admit(
        conn: &RecoveringConnection,
        fixture: &Fixture,
        request: &Value,
    ) -> Result<VerifiedHeld, Refusal> {
        let input = read_presentation(request)?;
        let policy = fixture.policy();
        let pre = precheck(&input, &policy)?;
        let fresh = consume_nonce(conn, AUDIENCE, &pre.nonce, &pre.account_key, policy.now)
            .await
            .expect("nonce store");
        if !fresh {
            return Err("nonce-replayed");
        }
        verify(&input, &pre, &policy)
    }

    fn refused(outcome: Result<VerifiedHeld, Refusal>) -> Refusal {
        match outcome {
            Ok(_) => panic!("presentation was accepted"),
            Err(code) => code,
        }
    }

    async fn conn() -> RecoveringConnection {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db.into()
    }

    async fn seed(
        conn: &RecoveringConnection,
        fixture: &Fixture,
        request: &Value,
    ) -> Result<(), Refusal> {
        let input = read_presentation(request)?;
        let pre = precheck(&input, &fixture.policy())?;
        record_nonce(
            conn,
            AUDIENCE,
            &pre.nonce,
            &pre.account_key,
            fixture.policy().now.unix_timestamp() + 3600,
        )
        .await
        .expect("nonce store");
        Ok(())
    }

    async fn outcome(fixture: &Fixture, request: &Value) -> Refusal {
        let conn = conn().await;
        if let Err(code) = seed(&conn, fixture, request).await {
            return code;
        }
        refused(admit(&conn, fixture, request).await)
    }

    #[tokio::test]
    async fn oc_vector_is_accepted_once_and_its_nonce_is_spent() {
        let (fixture, sd_jwt, message) = oc_case(NONCE);
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        let conn = conn().await;
        seed(&conn, &fixture, &request).await.expect("seed");
        let verified = admit(&conn, &fixture, &request)
            .await
            .expect("OC vector is accepted");
        assert_eq!(
            verified.claims.get("email").map(String::as_str),
            Some("alice@example.com")
        );
        assert_eq!(
            refused(admit(&conn, &fixture, &request).await),
            "nonce-replayed"
        );
    }

    /// Requirement and policy projection for `validate_held_email_admission`. The projection
    /// pins the digest of the request-local requirement the presenter sends.
    fn held_requirement_and_policy() -> (Value, Value) {
        let requirement = held_requirement();
        let policy = policy_for(&requirement);
        (requirement, policy)
    }

    fn held_requirement() -> Value {
        json!({
            "type": "TinyCloudCredentialRequirement",
            "version": 1,
            "profile": {"id": PROFILE, "version": PROFILE_VERSION},
            "credentialType": {"id": VCT, "version": 1},
            "claims": {"email": "alice@example.com", "emailDomain": "example.com"},
            "maxAgeSeconds": 31_536_000,
        })
    }

    /// The policy projection that binds `requirement` by its digest.
    fn policy_for(requirement: &Value) -> Value {
        json!({"credentialRequirement": {
            "type": "TinyCloudPolicyCredentialRequirement",
            "version": 1,
            "requirementDigest": canonical_digest_base64url(requirement),
            "descriptorDigest": b64url(&sha256(b"held-email-descriptor")),
            "issuerDid": TEST_ISSUER,
            "issuerKid": TEST_KID,
            "profile": requirement["profile"],
            "credentialType": requirement["credentialType"],
        }})
    }

    /// The held requirement with `edit` applied, bound by a digest computed after the edit.
    fn held_case(edit: impl FnOnce(&mut Value)) -> (Value, Value) {
        let mut requirement = held_requirement();
        edit(&mut requirement);
        let policy = policy_for(&requirement);
        (requirement, policy)
    }

    fn handler_runtime(
        conn: &RecoveringConnection,
        key: &SigningKey,
        held: bool,
    ) -> PolicyV3Runtime {
        let runtime = PolicyV3Runtime::new(
            conn.clone(),
            "did:web:node.example",
            StaticSecret::new(vec![7; 32]).unwrap(),
        )
        .with_credential_issuers(IssuerSet::load(&[issuer_config(key)]).unwrap());
        if !held {
            return runtime;
        }
        runtime
            .with_held_credentials(&HeldCredentialsConfig {
                enabled: true,
                audience: Some(AUDIENCE.to_owned()),
            })
            .unwrap()
    }

    /// Runs `validate_held_email_admission` as `mint` does and returns only the outcome code.
    async fn handler_admit(
        runtime: &PolicyV3Runtime,
        requirement: &Value,
        policy: &Value,
        presentation: &Value,
        caller: &str,
        consume: bool,
    ) -> Result<(), String> {
        let context = ClaimPresentationContext {
            challenge_id: "held-test-challenge",
            nonce: NONCE,
            policy_cid: "held-test-policy",
            owner_did: CALLER,
            recipient_did: "did:web:verifier.example",
            authenticated_account_owner: Some(caller),
            now: OffsetDateTime::parse(NOW, &Rfc3339).unwrap(),
        };
        validate_held_email_admission(
            requirement,
            presentation,
            policy,
            &context,
            runtime,
            consume,
        )
        .await
        .map(|_| ())
        .map_err(|(_, code)| code)
    }

    /// Records the nonce the way the nonce mint route would. The route is tracked separately,
    /// so tests stand in for it here.
    async fn seed_handler(conn: &RecoveringConnection, key: &SigningKey, presentation: &Value) {
        seed(conn, &own_fixture(key), presentation)
            .await
            .expect("seed");
    }

    #[tokio::test]
    async fn handler_refuses_held_presentations_when_the_flag_is_off() {
        let key = test_key();
        let (requirement, policy) = held_requirement_and_policy();
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, false);
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("held-credentials-disabled".to_owned())
        );
    }

    #[tokio::test]
    async fn held_admission_is_accepted_once_then_replayed() {
        let key = test_key();
        let (requirement, policy) = held_requirement_and_policy();
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true)
            .await
            .expect("honest held presentation is admitted");
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("nonce-replayed".to_owned())
        );
    }

    /// Spec §4.4: the nonce is spent before any signature check, so a refused presentation
    /// cannot be retried against the same nonce.
    #[tokio::test]
    async fn refused_presentation_still_spends_the_nonce() {
        let key = test_key();
        let other = SigningKey::from_bytes(&[9; 32]);
        let (requirement, policy) = held_requirement_and_policy();
        let presentation = request_for(&credential(&other, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("bad-signature".to_owned())
        );
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("nonce-replayed".to_owned())
        );
    }

    /// Spec §4.4 step 2: a nonce is consumed for the caller only. Another account presenting
    /// the subject's nonce spends nothing, so the subject can still admit it.
    #[tokio::test]
    async fn other_account_cannot_spend_the_subjects_nonce() {
        let key = test_key();
        let (requirement, policy) = held_requirement_and_policy();
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(
                &runtime,
                &requirement,
                &policy,
                &presentation,
                OTHER_ACCOUNT,
                true
            )
            .await,
            Err("nonce-replayed".to_owned())
        );
        handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true)
            .await
            .expect("subject still holds its unspent nonce");
    }

    #[tokio::test]
    async fn locked_reevaluation_verifies_without_spending_the_nonce_again() {
        let key = test_key();
        let (requirement, policy) = held_requirement_and_policy();
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true)
            .await
            .expect("first admission");
        handler_admit(
            &runtime,
            &requirement,
            &policy,
            &presentation,
            CALLER,
            false,
        )
        .await
        .expect("locked re-evaluation accepts the spent nonce");
    }

    #[tokio::test]
    async fn requirement_for_another_email_is_not_satisfied() {
        let key = test_key();
        let (requirement, policy) = held_case(|r| r["claims"]["email"] = json!("bob@example.com"));
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("credential-requirement-not-satisfied".to_owned())
        );
    }

    /// The max age is checked before the nonce is spent, so a refused requirement leaves the
    /// nonce available for a correct one.
    #[tokio::test]
    async fn max_age_other_than_the_pinned_year_is_refused_before_the_nonce_is_spent() {
        let key = test_key();
        let (requirement, policy) = held_case(|r| r["maxAgeSeconds"] = json!(60));
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("credential-requirement-invalid".to_owned())
        );
        let (good, good_policy) = held_requirement_and_policy();
        handler_admit(&runtime, &good, &good_policy, &presentation, CALLER, true)
            .await
            .expect("the nonce is still unspent after the refused max age");
    }

    #[tokio::test]
    async fn issuer_kid_other_than_the_pinned_kid_is_not_accepted() {
        let key = test_key();
        let (requirement, mut policy) = held_requirement_and_policy();
        policy["credentialRequirement"]["issuerKid"] = json!("other-kid");
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("issuer-not-accepted".to_owned())
        );
    }

    #[tokio::test]
    async fn upper_case_email_disclosure_is_refused() {
        let key = test_key();
        let disclosures = vec![
            disclosure("upper-salt-email", "email", "Alice@example.com"),
            disclosure("upper-salt-domain", "emailDomain", "example.com"),
        ];
        let sd_jwt = mint(
            &key,
            &default_header().to_string(),
            &default_payload(&disclosures).to_string(),
            &disclosures,
        );
        let presentation = request_for(&sd_jwt);
        let (requirement, policy) = held_requirement_and_policy();
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("bad-disclosure".to_owned())
        );
    }

    #[tokio::test]
    async fn credential_type_other_than_the_held_vct_is_a_type_mismatch() {
        let key = test_key();
        let (requirement, policy) =
            held_case(|r| r["credentialType"]["id"] = json!("opencredentials.other/v1"));
        let presentation = request_for(&credential(&key, default_header(), |_| {}));
        let conn = conn().await;
        let runtime = handler_runtime(&conn, &key, true);
        seed_handler(&conn, &key, &presentation).await;
        assert_eq!(
            handler_admit(&runtime, &requirement, &policy, &presentation, CALLER, true).await,
            Err("credential-type-mismatch".to_owned())
        );
    }

    #[tokio::test]
    async fn flipped_siwe_signature_is_refused() {
        let (fixture, sd_jwt, message) = oc_case("heldtestnonce0000000002");
        let mut signature = sign_siwe(&message);
        let last = signature.pop().unwrap();
        signature.push(if last == '0' { '1' } else { '0' });
        let request = body(&sd_jwt, &message, &signature);
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe-signature");
    }

    #[tokio::test]
    async fn minted_credential_is_accepted_with_declared_disclosures() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let conn = conn().await;
        let request = request_for(&sd_jwt);
        seed(&conn, &fixture, &request).await.expect("seed");
        let verified = admit(&conn, &fixture, &request)
            .await
            .expect("minted credential is accepted");
        assert_eq!(
            verified.claims.get("emailDomain").map(String::as_str),
            Some("example.com")
        );
    }

    #[tokio::test]
    async fn missing_kid_header_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let header = json!({"alg": "EdDSA", "typ": "vc+sd-jwt"});
        let sd_jwt = credential(&key, header, |_| {});
        assert_eq!(outcome(&fixture, &request_for(&sd_jwt)).await, "bad-header");
    }

    /// TC-1541 item 1. With the explicit list and a legacy single issuer loaded together, a
    /// kid-less header is still refused on the held path, and a kid-bearing credential from
    /// the explicit entry is still accepted.
    #[tokio::test]
    async fn kidless_header_is_refused_with_the_combined_issuer_set() {
        let key = test_key();
        let legacy_did = "did:web:legacy-held.example";
        let legacy_kid = "did:web:legacy-held.example#k1";
        let legacy_key = IssuerKey::new(
            legacy_did,
            VCT,
            1,
            legacy_kid,
            SigningKey::from_bytes(&[9u8; 32])
                .verifying_key()
                .to_bytes(),
        );
        let set = IssuerSet::load_with_legacy(&[issuer_config(&key)], Some(&legacy_key)).unwrap();
        assert!(set.resolve_pinned_issuer(legacy_did, legacy_kid).is_some());
        let fixture = Fixture::new(set, TEST_ISSUER);

        let kidless = credential(&key, json!({"alg": "EdDSA", "typ": "vc+sd-jwt"}), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&kidless)).await,
            "bad-header"
        );

        let conn = conn().await;
        let request = request_for(&credential(&key, default_header(), |_| {}));
        seed(&conn, &fixture, &request).await.expect("seed");
        admit(&conn, &fixture, &request)
            .await
            .expect("kid-bearing credential is accepted with the combined set");
    }

    /// TC-1541 item 2. Dalek's `verify` accepts a signature whose `R` is the identity point
    /// (small order) when `S·B = k·A`; `verify_strict` refuses it. The forgery is built from
    /// the test key's own secret scalar, so the vector is a genuine instance of that case.
    #[tokio::test]
    async fn small_order_r_signature_is_refused_on_the_held_path() {
        use curve25519_dalek::{
            constants::ED25519_BASEPOINT_POINT, edwards::CompressedEdwardsY, scalar::Scalar,
            traits::Identity,
        };
        use ed25519_dalek::Verifier;

        let key = test_key();
        let verifying = key.verifying_key();
        let disclosures = email_disclosures();
        let header = default_header().to_string();
        let payload = default_payload(&disclosures).to_string();
        let input = signing_input(&header, &payload);

        // RFC 8032 secret scalar: the clamped low half of SHA-512(seed).
        let expanded = sha2::Sha512::digest(key.to_bytes());
        let mut clamped = [0u8; 32];
        clamped.copy_from_slice(&expanded[..32]);
        clamped[0] &= 248;
        clamped[31] &= 127;
        clamped[31] |= 64;
        let secret = Scalar::from_bytes_mod_order(clamped);
        assert_eq!(
            (secret * ED25519_BASEPOINT_POINT).compress().to_bytes(),
            verifying.to_bytes(),
            "derived scalar must match the pinned public key"
        );

        // R is the identity (small order). With S = k·a, S·B − k·A = identity = R.
        let r = CompressedEdwardsY::identity();
        let k = Scalar::from_hash(
            sha2::Sha512::new()
                .chain_update(r.as_bytes())
                .chain_update(verifying.to_bytes())
                .chain_update(input.as_bytes()),
        );
        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(r.as_bytes());
        signature[32..].copy_from_slice((k * secret).as_bytes());
        let forged = Signature::from_bytes(&signature);

        // The vector discriminates: plain `verify` accepts it, `verify_strict` refuses it.
        assert!(verifying.verify(input.as_bytes(), &forged).is_ok());
        assert!(verifying.verify_strict(input.as_bytes(), &forged).is_err());

        let sd_jwt = assemble(&input, &signature, &disclosures);
        let fixture = own_fixture(&key);
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-signature"
        );
    }

    #[tokio::test]
    async fn typ_other_than_vc_sd_jwt_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let header = json!({"alg": "EdDSA", "typ": "JWT", "kid": TEST_KID});
        let sd_jwt = credential(&key, header, |_| {});
        assert_eq!(outcome(&fixture, &request_for(&sd_jwt)).await, "bad-header");
    }

    #[tokio::test]
    async fn duplicate_payload_key_is_refused_even_when_signed() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let disclosures = email_disclosures();
        let payload = default_payload(&disclosures).to_string().replacen(
            '{',
            "{\"jti\":\"urn:uuid:7c1e4b2a-9d3f-4e5a-8b6c-0d1e2f3a4b5c\",",
            1,
        );
        let sd_jwt = mint(&key, &default_header().to_string(), &payload, &disclosures);
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-payload"
        );
    }

    #[tokio::test]
    async fn payload_altered_after_signing_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let disclosures = email_disclosures();
        let header = default_header().to_string();
        let signed = signing_input(&header, &default_payload(&disclosures).to_string());
        let mut altered = default_payload(&disclosures);
        altered["jti"] = json!("urn:uuid:9e8d7c6b-5a4f-4e3d-8c2b-1a0f9e8d7c6b");
        let signature = key.sign(signed.as_bytes()).to_bytes();
        let sd_jwt = assemble(
            &signing_input(&header, &altered.to_string()),
            &signature,
            &disclosures,
        );
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-signature"
        );
    }

    #[tokio::test]
    async fn descriptor_digest_is_refused_for_the_email_row() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |p| {
            p["descriptorDigest"] = json!("unexpected");
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-payload"
        );
    }

    #[tokio::test]
    async fn repeated_sd_digest_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |p| {
            let first = p["_sd"][0].clone();
            p["_sd"].as_array_mut().unwrap().push(first);
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-payload"
        );
    }

    #[tokio::test]
    async fn header_member_outside_alg_typ_kid_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let mut header = default_header();
        header["x5c"] = json!(["AAAA"]);
        let sd_jwt = credential(&key, header, |_| {});
        assert_eq!(outcome(&fixture, &request_for(&sd_jwt)).await, "bad-header");
    }

    #[tokio::test]
    async fn non_v4_jti_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |p| {
            p["jti"] = json!("urn:uuid:held-test-0001");
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-payload"
        );
    }

    #[tokio::test]
    async fn oversized_presentation_is_refused_before_decoding() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = "a".repeat(16385);
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-presentation"
        );
    }

    #[test]
    fn did_pkh_accepts_all_lowercase_or_exact_eip55_only() {
        assert!(parse_pkh(CALLER).is_some());
        let lower = CALLER.to_ascii_lowercase();
        let upper = format!("did:pkh:eip155:1:0x{}", HOLDER[2..].to_ascii_uppercase());
        assert!(parse_pkh(&lower).is_some());
        assert!(parse_pkh(&upper).is_none());
    }

    #[test]
    fn siwe_address_requires_the_exact_eip55_checksum() {
        let lowered = siwe_message(NONCE, "x").replacen(HOLDER, &HOLDER.to_ascii_lowercase(), 1);
        assert_eq!(parse_siwe(&lowered).err(), Some(BAD_SIWE));
        assert!(parse_siwe(&siwe_message(NONCE, "x")).is_ok());
    }

    #[test]
    fn fractional_seconds_are_capped_at_nine_digits() {
        assert!(rfc3339_shape("2026-01-01T00:00:00.123456789Z"));
        assert!(!rfc3339_shape("2026-01-01T00:00:00.1234567890Z"));
    }

    #[test]
    fn seconds_must_be_at_most_59() {
        assert!(rfc3339_shape("2026-01-01T00:00:59Z"));
        assert!(!rfc3339_shape("2026-01-01T00:00:60Z"));
        assert!(!rfc3339_shape("2026-01-01T00:00:61Z"));
    }

    #[test]
    fn jti_must_be_a_lowercase_v4_uuid_urn() {
        assert!(is_uuid_v4_urn(
            "urn:uuid:5f1c9a2e-7b3d-4e8a-9c61-2d4b8e7f0a13"
        ));
        assert!(!is_uuid_v4_urn(
            "urn:uuid:5F1C9A2E-7B3D-4E8A-9C61-2D4B8E7F0A13"
        ));
        assert!(!is_uuid_v4_urn(
            "urn:uuid:5f1c9a2e-7b3d-1e8a-9c61-2d4b8e7f0a13"
        ));
        assert!(!is_uuid_v4_urn(
            "urn:uuid:5f1c9a2e-7b3d-4e8a-1c61-2d4b8e7f0a13"
        ));
    }

    #[test]
    fn email_domain_must_be_ascii_and_email_must_not_start_or_end_with_at() {
        let check = |name: &str, value: &str| {
            let mut claims = BTreeMap::new();
            claims.insert(name.to_owned(), value.to_owned());
            validate_disclosed(&claims)
        };
        assert_eq!(check("emailDomain", "exämple.com"), Err(BAD_DISCLOSURE));
        assert_eq!(check("email", "@example.com"), Err(BAD_DISCLOSURE));
        assert_eq!(check("email", "user@"), Err(BAD_DISCLOSURE));
        assert_eq!(check("email", "user@example.com"), Ok(()));
    }

    #[tokio::test]
    async fn lifetime_over_365_days_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |p| {
            p["exp"] = json!(IAT + 366 * DAY)
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-lifetime"
        );
    }

    #[tokio::test]
    async fn status_other_than_none_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |p| {
            p["status"] = json!({"method": "revoked"})
        });
        assert_eq!(outcome(&fixture, &request_for(&sd_jwt)).await, "bad-status");
    }

    #[tokio::test]
    async fn subject_with_invalid_eip55_casing_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let mangled = CALLER.replacen("Fd6", "FD6", 1);
        let sd_jwt = credential(&key, default_header(), |p| {
            p["sub"] = json!(mangled);
            p["holderBinding"]["did"] = json!(mangled);
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-subject"
        );
    }

    #[tokio::test]
    async fn subject_with_all_lowercase_body_is_accepted_and_reported_checksummed() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let lower = CALLER.to_ascii_lowercase();
        let sd_jwt = credential(&key, default_header(), |p| {
            p["sub"] = json!(lower);
            p["holderBinding"]["did"] = json!(lower);
        });
        let request = request_for(&sd_jwt);
        let conn = conn().await;
        seed(&conn, &fixture, &request).await.expect("seed");
        let verified = admit(&conn, &fixture, &request)
            .await
            .expect("all-lowercase body is accepted");
        assert_eq!(verified.subject, CALLER);
        assert_eq!(verified.subject_address, HOLDER.to_ascii_lowercase());
    }

    #[tokio::test]
    async fn disclosure_without_matching_digest_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let mut disclosures = email_disclosures();
        disclosures.push(disclosure("salt-stray", "emailDomain", "other.example"));
        let payload = default_payload(&email_disclosures()).to_string();
        let sd_jwt = mint(&key, &default_header().to_string(), &payload, &disclosures);
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-disclosure"
        );
    }

    #[tokio::test]
    async fn credential_at_or_after_expiry_is_refused() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.now = OffsetDateTime::from_unix_timestamp(IAT + 30 * DAY).unwrap();
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(outcome(&fixture, &request_for(&sd_jwt)).await, "expired");
    }

    #[tokio::test]
    async fn credential_before_not_before_is_refused() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.now = OffsetDateTime::from_unix_timestamp(IAT - 60).unwrap();
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "not-yet-valid"
        );
    }

    #[tokio::test]
    async fn siwe_uri_authority_other_than_audience_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let message = siwe_message(NONCE, &sd_jwt).replacen(
            "URI: https://verifier.example",
            "URI: https://evil.example",
            1,
        );
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe");
    }

    #[test]
    fn caller_must_be_the_subject_account() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.caller = OTHER_ACCOUNT.to_owned();
        let sd_jwt = credential(&key, default_header(), |_| {});
        let request = request_for(&sd_jwt);
        let input = read_presentation(&request).unwrap();
        let policy = fixture.policy();
        let pre = precheck(&input, &policy).unwrap();
        assert_eq!(
            refused(verify(&input, &pre, &policy)),
            "nonce-account-mismatch"
        );
    }

    #[tokio::test]
    async fn issuer_stopped_at_now_is_refused() {
        let key = test_key();
        let mut config = issuer_config(&key);
        config.not_after = Some("2026-01-01T00:30:00Z".to_owned());
        let fixture = Fixture::new(IssuerSet::load(&[config]).unwrap(), TEST_ISSUER);
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "issuer-stopped"
        );
    }

    #[tokio::test]
    async fn credential_issued_after_issuer_retirement_is_refused() {
        let key = test_key();
        let mut config = issuer_config(&key);
        config.retired_at = Some("2025-12-31T23:00:00Z".to_owned());
        let fixture = Fixture::new(IssuerSet::load(&[config]).unwrap(), TEST_ISSUER);
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "issuer-retired"
        );
    }

    #[tokio::test]
    async fn issuer_outside_the_policy_accepted_list_is_refused() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.issuers = vec![AcceptedIssuer {
            did: "did:web:other.example".to_owned(),
            kid: None,
        }];
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "issuer-not-accepted"
        );
    }

    #[tokio::test]
    async fn policy_kid_pin_must_match_the_presented_kid() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.issuers = vec![AcceptedIssuer {
            did: TEST_ISSUER.to_owned(),
            kid: Some(format!("{TEST_ISSUER}#k2")),
        }];
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "issuer-not-accepted"
        );
    }

    #[tokio::test]
    async fn credential_type_outside_the_issuer_entry_is_refused() {
        let key = test_key();
        let mut config = issuer_config(&key);
        config.vcts = vec!["urn:example:other-credential".to_owned()];
        let fixture = Fixture::new(IssuerSet::load(&[config]).unwrap(), TEST_ISSUER);
        let sd_jwt = credential(&key, default_header(), |_| {});
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "profile-mismatch"
        );
    }

    #[tokio::test]
    async fn siwe_domain_other_than_audience_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let message = siwe_message(NONCE, &sd_jwt).replacen(
            &format!("{AUDIENCE} wants"),
            "evil.example wants",
            1,
        );
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe");
    }

    #[tokio::test]
    async fn siwe_resource_must_hash_the_presented_sd_jwt() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let message = siwe_message(NONCE, "a-different-sd-jwt");
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe");
    }

    #[tokio::test]
    async fn siwe_expiration_time_in_the_past_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let message = siwe_message(NONCE, &sd_jwt).replacen(
            &format!("Issued At: {ISSUED_AT}"),
            &format!("Issued At: {ISSUED_AT}\nExpiration Time: 2025-12-31T00:00:00Z"),
            1,
        );
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe");
    }

    #[tokio::test]
    async fn siwe_expiration_is_compared_at_millisecond_precision() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.now = OffsetDateTime::parse(NOW, &Rfc3339).unwrap();
        let sd_jwt = credential(&key, default_header(), |_| {});
        // TS keeps milliseconds only: `NOW` plus 0.5ms truncates to `NOW`, which is not after `now`.
        let sub_ms = NOW.replace('Z', ".0005Z");
        let message = siwe_message(NONCE, &sd_jwt).replacen(
            &format!("Issued At: {ISSUED_AT}"),
            &format!("Issued At: {ISSUED_AT}\nExpiration Time: {sub_ms}"),
            1,
        );
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe");
    }

    #[tokio::test]
    async fn siwe_not_before_is_compared_at_millisecond_precision() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.now = OffsetDateTime::parse(NOW, &Rfc3339).unwrap();
        let sd_jwt = credential(&key, default_header(), |_| {});
        // TS keeps milliseconds only: `NOW` plus 0.5ms truncates to `NOW`, so `now` is not before it.
        let sub_ms = NOW.replace('Z', ".0005Z");
        let message = siwe_message(NONCE, &sd_jwt).replacen(
            &format!("Issued At: {ISSUED_AT}"),
            &format!("Issued At: {ISSUED_AT}\nNot Before: {sub_ms}"),
            1,
        );
        let request = body(&sd_jwt, &message, &sign_siwe(&message));
        let conn = conn().await;
        seed(&conn, &fixture, &request).await.expect("seed");
        admit(&conn, &fixture, &request)
            .await
            .expect("not-before truncates to NOW, so it is not in the future");
    }

    #[tokio::test]
    async fn siwe_signed_by_another_key_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |_| {});
        let message = siwe_message(NONCE, &sd_jwt);
        // Anvil account 1: a valid secp256k1 key whose address is not the subject.
        let other_key = "59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d";
        let request = body(&sd_jwt, &message, &sign_siwe_with(other_key, &message));
        assert_eq!(outcome(&fixture, &request).await, "bad-siwe-signature");
    }

    #[tokio::test]
    async fn holder_binding_must_name_the_subject() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |payload| {
            payload["holderBinding"]["did"] = json!(OTHER_ACCOUNT);
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-holder-binding"
        );
    }

    #[tokio::test]
    async fn subject_on_another_chain_is_refused() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let other_chain = format!("did:pkh:eip155:10:{HOLDER}");
        let sd_jwt = credential(&key, default_header(), |payload| {
            payload["sub"] = json!(other_chain);
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-subject"
        );
    }

    #[tokio::test]
    async fn payload_iss_must_name_the_kid_issuer() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let sd_jwt = credential(&key, default_header(), |payload| {
            payload["iss"] = json!("did:web:other.example");
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-payload"
        );
    }

    #[tokio::test]
    async fn disclosure_must_be_listed_in_sd() {
        let key = test_key();
        let fixture = own_fixture(&key);
        let first = digest(&email_disclosures()[0]);
        let sd_jwt = credential(&key, default_header(), |payload| {
            payload["_sd"] = json!([first]);
        });
        assert_eq!(
            outcome(&fixture, &request_for(&sd_jwt)).await,
            "bad-disclosure"
        );
    }

    #[test]
    fn malformed_caller_account_is_a_client_refusal_not_a_server_fault() {
        let key = test_key();
        let mut fixture = own_fixture(&key);
        fixture.caller = "did:pkh:eip155:1:not-an-address".to_owned();
        let sd_jwt = credential(&key, default_header(), |_| {});
        let request = request_for(&sd_jwt);
        let input = read_presentation(&request).unwrap();
        assert_eq!(
            precheck(&input, &fixture.policy()).err(),
            Some("account-owner-invalid")
        );
    }

    #[tokio::test]
    async fn nonce_is_spent_only_by_the_account_it_was_recorded_for() {
        let conn = conn().await;
        let owner = CALLER.to_ascii_lowercase();
        let now = OffsetDateTime::from_unix_timestamp(1_000_000).unwrap();
        record_nonce(&conn, AUDIENCE, NONCE, &owner, 1_000_600)
            .await
            .unwrap();
        assert!(!consume_nonce(&conn, AUDIENCE, NONCE, OTHER_ACCOUNT, now)
            .await
            .unwrap());
        assert!(consume_nonce(&conn, AUDIENCE, NONCE, &owner, now)
            .await
            .unwrap());
        assert!(!consume_nonce(&conn, AUDIENCE, NONCE, &owner, now)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn expired_nonce_is_refused_and_spends_nothing() {
        let conn = conn().await;
        let owner = CALLER.to_ascii_lowercase();
        record_nonce(&conn, AUDIENCE, NONCE, &owner, 1_000_600)
            .await
            .unwrap();
        let late = OffsetDateTime::from_unix_timestamp(1_000_601).unwrap();
        assert!(!consume_nonce(&conn, AUDIENCE, NONCE, &owner, late)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn nonce_expiry_boundary_is_exclusive() {
        let conn = conn().await;
        let owner = CALLER.to_ascii_lowercase();
        record_nonce(&conn, AUDIENCE, NONCE, &owner, 1_000_600)
            .await
            .unwrap();
        let at_expiry = OffsetDateTime::from_unix_timestamp(1_000_600).unwrap();
        assert!(!consume_nonce(&conn, AUDIENCE, NONCE, &owner, at_expiry)
            .await
            .unwrap());
    }

    #[tokio::test]
    async fn expired_rows_are_pruned_on_consume() {
        let conn = conn().await;
        let owner = CALLER.to_ascii_lowercase();
        record_nonce(&conn, AUDIENCE, "stale", &owner, 1_000_100)
            .await
            .unwrap();
        record_nonce(&conn, AUDIENCE, NONCE, &owner, 1_000_600)
            .await
            .unwrap();
        let now = OffsetDateTime::from_unix_timestamp(1_000_200).unwrap();
        assert!(consume_nonce(&conn, AUDIENCE, NONCE, &owner, now)
            .await
            .unwrap());
        let remaining = held_credential_nonce::Entity::find()
            .all(&conn)
            .await
            .unwrap();
        assert!(remaining.is_empty());
    }

    #[test]
    fn kidless_lookup_never_resolves_a_pinned_key() {
        let key = test_key();
        let configured = IssuerSet::load(&[issuer_config(&key)]).unwrap();
        assert!(configured
            .resolve_pinned_issuer(TEST_ISSUER, TEST_KID)
            .is_some());
        assert!(configured.resolve_pinned_issuer(TEST_ISSUER, "").is_none());

        let legacy_key = IssuerKey::new(
            TEST_ISSUER,
            VCT,
            1,
            TEST_KID,
            key.verifying_key().to_bytes(),
        );
        let legacy = IssuerSet::from_legacy(&legacy_key);
        assert!(legacy
            .resolve_pinned_issuer(TEST_ISSUER, TEST_KID)
            .is_some());
        assert!(legacy.resolve_pinned_issuer(TEST_ISSUER, "").is_none());
    }

    /// Replays the TS differential table, `tests/fixtures/held-email-v1/s1-differential.json`,
    /// generated from the published `@tinycloud/sdk-core` 3.3.0-beta.37 `held-credentials` verifier.
    #[tokio::test]
    async fn s1_differential_table_matches_ts_verdicts() {
        let table: Value = serde_json::from_str(include_str!(
            "../tests/fixtures/held-email-v1/s1-differential.json"
        ))
        .unwrap();
        let cases = table.as_array().unwrap();
        let mut diverging = Vec::new();
        for case in cases {
            let name = case["name"].as_str().unwrap();
            let expected = case["ts"]["code"].as_str().unwrap();
            let actual = replay(case).await;
            if actual != expected {
                diverging.push(format!("{name}: rust={actual} ts={expected}"));
            }
        }
        assert!(
            diverging.is_empty(),
            "{} of {} cases diverge from TS:\n{}",
            diverging.len(),
            cases.len(),
            diverging.join("\n")
        );
    }

    /// One table case through the production order (precheck, consume nonce, verify).
    /// Returns `"ok"` on accept with the TS issuer and subject, otherwise the Rust refusal.
    async fn replay(case: &Value) -> String {
        let policy = &case["policy"];
        assert_eq!(policy["audience"], AUDIENCE);
        let configured: Vec<CredentialIssuerConfig> =
            match serde_json::from_value(policy["issuers"].clone()) {
                Ok(configured) => configured,
                Err(err) => return format!("config-invalid: {err}"),
            };
        let set = match IssuerSet::load(&configured) {
            Ok(set) => set,
            // Rust rejects a bad set at startup (`credential_issuer_set()?` in lib.rs), so no
            // presentation reaches verify. TS reports the same condition per presentation.
            Err(_) => return "bad-issuer-set".to_owned(),
        };
        let fixture = Fixture {
            set,
            issuers: policy["acceptedIssuers"]
                .as_array()
                .unwrap()
                .iter()
                .map(|issuer| AcceptedIssuer {
                    did: issuer["issuerDid"].as_str().unwrap().to_owned(),
                    kid: issuer["kid"].as_str().map(str::to_owned),
                })
                .collect(),
            profiles: policy["acceptedProfiles"]
                .as_array()
                .unwrap()
                .iter()
                .map(|profile| AcceptedProfile {
                    id: profile["id"].as_str().unwrap().to_owned(),
                    version: profile["version"].as_i64().unwrap(),
                })
                .collect(),
            now: OffsetDateTime::parse(policy["now"].as_str().unwrap(), &Rfc3339).unwrap(),
            caller: policy["caller"].as_str().unwrap().to_owned(),
        };
        let conn = conn().await;
        for entry in case["nonceStore"].as_array().unwrap() {
            let (audience, nonce) = entry["key"].as_str().unwrap().split_once('\n').unwrap();
            record_nonce(
                &conn,
                audience,
                nonce,
                &parse_pkh(entry["account"].as_str().unwrap())
                    .expect("nonceStore account is did:pkh")
                    .canonical(),
                fixture.now.unix_timestamp() + 3600,
            )
            .await
            .expect("nonce store");
        }
        let request = json!({"sdJwt": case["sdJwt"], "siwe": case["siwe"]});
        match admit(&conn, &fixture, &request).await {
            Ok(verified)
                if Some(verified.issuer.as_str()) == case["ts"]["issuer"].as_str()
                    && Some(verified.subject.as_str()) == case["ts"]["subject"].as_str() =>
            {
                "ok".to_owned()
            }
            Ok(_) => "ok-identity-diverges".to_owned(),
            Err(code) => code.to_owned(),
        }
    }

    #[test]
    fn siwe_uri_must_be_https_with_no_userinfo_and_the_exact_audience_host() {
        let audience = "tinycloud.example";
        for (uri, expected) in [
            ("https://tinycloud.example/nonce", true),
            ("https://TINYCLOUD.example/", true),
            ("https://tinycloud.example:443/x?y#z", true),
            ("https://tinycloud.example:8443/", false),
            ("https://user@tinycloud.example/", false),
            ("https://user:pw@tinycloud.example/", false),
            ("https://tinycloud.example.evil/", false),
            ("https://evil.example/@tinycloud.example", false),
            ("https://tinycloud.example./", false),
            ("http://tinycloud.example/", false),
            ("tinycloud.example", false),
            ("", false),
        ] {
            assert_eq!(uri_matches_audience(uri, audience), expected, "{uri}");
        }
    }

    #[test]
    fn siwe_uri_origin_includes_the_audience_port() {
        let audience = "verifier.example:8443";
        for (uri, expected) in [
            ("https://verifier.example:8443/nonce", true),
            ("https://VERIFIER.example:8443/", true),
            ("https://verifier.example/", false),
            ("https://verifier.example:9443/", false),
            ("https://verifier.example:443/", false),
        ] {
            assert_eq!(uri_matches_audience(uri, audience), expected, "{uri}");
        }
    }

    /// High-S SIWE signatures (`n - s` with the flipped recovery byte) are refused:
    /// `recover_eip191_address` verifies with `verify_prehash`, which enforces low-S.
    /// TS beta.37 recovers them (no low-S check); the divergence is tracked on TC-1540.
    #[test]
    fn siwe_high_s_signature_is_refused_and_low_s_still_recovers() {
        use k256::elliptic_curve::PrimeField;
        let message = siwe_message(NONCE, "held-placeholder~");
        let low = sign_siwe(&message);
        let bytes = hex::decode(low.trim_start_matches("0x")).unwrap();
        let mut s_bytes = [0u8; 32];
        s_bytes.copy_from_slice(&bytes[32..64]);
        let s = k256::Scalar::from_repr(s_bytes.into()).unwrap();
        let high_s = (-s).to_bytes();
        assert_ne!(&high_s[..], &bytes[32..64]);
        let mut high = bytes[..32].to_vec();
        high.extend_from_slice(&high_s);
        high.push(if bytes[64] == 27 { 28 } else { 27 });
        let prefixed_message = message.as_bytes();
        assert_eq!(recover_eip191_address(prefixed_message, &high), None);
        assert_eq!(
            recover_eip191_address(prefixed_message, &bytes)
                .unwrap()
                .to_lowercase(),
            HOLDER.to_lowercase()
        );
    }
}
