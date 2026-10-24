//! The short link a delivery authorization is made for, and the checks on the
//! record fetched for it.
//!
//! The link is `<return_origin>/s/<id>#v=4&k=<key>&c=<cid>`: the key and the
//! content id ride in the fragment and never reach the links API. The node
//! reads the record for `<id>` from its configured API, then checks, in order:
//!
//! 1. `X-Link-Record` parses, the header is strict, `type` is `share` and the
//!    record is signed;
//! 2. `size` is the received length and `CID(body) == bodyCid == c`;
//! 3. the header signature verifies under the strict Ed25519 rule (canonical
//!    `S`, canonical prime-order `A` and `R`, then the equation) over
//!    `SHA-256("xyz.tinycloud.links/header/v1\0" ‖ JCS(header))`;
//! 4. `expiresAt` is in the future;
//! 5. the body opens with the key from the link.
//!
//! The caller then binds the header issuer to the opened envelope's signer and
//! the registration owner and applies the registration's share expiry.
//!
//! Neither the link, nor the key, nor any text derived from them appears in an
//! error, a log line or a stored row: every type here that holds the key has a
//! redacting `Debug`, and every refusal is a fieldless variant.

use crate::links_fetch::{FetchedLink, LinkId, MAX_LINK_BODY_BYTES, MAX_LINK_RECORD_HEADER_BYTES};
use crate::policy_v3::{
    SEALED_ENVELOPE_AAD as SEALED_AAD, SEALED_ENVELOPE_NONCE_BYTES as SEALED_NONCE_BYTES,
    SEALED_ENVELOPE_TAG_BYTES as SEALED_TAG_BYTES, SEALED_ENVELOPE_VERSION as SEALED_VERSION,
};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload as AeadPayload},
    Aes256Gcm, Nonce,
};
use base64::{decode_config, encode_config, URL_SAFE_NO_PAD};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tinycloud_auth::{ipld_core::cid::Cid, multihash_codetable::MultihashDigest};

/// The domain the links API's header signature is made under (§2.5).
const LINK_HEADER_DOMAIN: &[u8] = b"xyz.tinycloud.links/header/v1\0";
/// Version byte, nonce, tag and at least one byte of ciphertext.
const MIN_SEALED_BYTES: usize = 1 + SEALED_NONCE_BYTES + SEALED_TAG_BYTES + 1;
/// A short link is `origin + /s/ + 26 + #v=4&k= + 43 + &c= + 59`; this bounds
/// the work done on an oversize string before the exact grammar runs.
const MAX_LINK_BYTES: usize = 512;
const RAW_CODEC: u64 = 0x55;
const SHA2_256: u64 = 0x12;

/// A parsed short `v=4` link for a share. The key is private to this module
/// and the type has no `Debug` output that includes it.
#[derive(Clone)]
pub struct ShortLink {
    href: String,
    id: LinkId,
    key: [u8; 32],
    cid: String,
}

impl std::fmt::Debug for ShortLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ShortLink(..)")
    }
}

impl ShortLink {
    /// Parse `href` against the one origin the node accepts. Only the short
    /// form on the share path is accepted, and only as the exact string the
    /// grammar writes: a lowercase 26-character id, then the fragment
    /// `#v=4&k=<43 base64url>&c=<canonical raw sha2-256 CID>` and nothing
    /// else (no query, no other parameter, no other order, no other version).
    pub fn parse(href: &str, return_origin: &str) -> Option<Self> {
        if href.len() > MAX_LINK_BYTES {
            return None;
        }
        let rest = href.strip_prefix(return_origin)?.strip_prefix("/s/")?;
        let (id, fragment) = rest.split_once('#')?;
        let id = LinkId::parse(id)?;
        let parameters = fragment.strip_prefix("v=4&k=")?;
        let (key, cid) = parameters.split_once("&c=")?;
        if key.len() != 43 {
            return None;
        }
        let key: [u8; 32] = decode_strict(key)?.try_into().ok()?;
        if !is_canonical_raw_cid(cid) {
            return None;
        }
        Some(Self {
            href: href.to_owned(),
            id,
            key,
            cid: cid.to_owned(),
        })
    }

    /// The exact submitted link, fragment included.
    pub fn href(&self) -> &str {
        &self.href
    }

    pub fn id(&self) -> &LinkId {
        &self.id
    }

    /// The link's `c`: the CID of the sealed body.
    pub fn cid(&self) -> &str {
        &self.cid
    }
}

/// Why a record or its body failed a check. Fieldless on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkRefusal {
    /// `X-Link-Record` is not strict base64url, not JSON, or the header or
    /// signature object is not exactly the contract's shape.
    RecordShape,
    /// The header type is not `share`.
    NotShare,
    /// A `share` record without a signature.
    Unsigned,
    /// `size` is not the received length, or the body is over the share cap.
    SizeMismatch,
    /// `CID(body)` is not `bodyCid`.
    BodyCidMismatch,
    /// `bodyCid` is not the link's `c`.
    LinkCidMismatch,
    /// The issuer is not a canonical, prime-order Ed25519 `did:key`, or the
    /// signature does not verify under the strict rule.
    BadSignature,
    /// `expiresAt` is not in the future, or is later than the share's expiry.
    Expired,
    /// The body is not a sealed envelope that opens with the key in the link.
    BodyOpenFailed,
    /// The header issuer, the opened envelope's signer and the registration
    /// owner are not one key.
    IssuerBindingMismatch,
}

/// A record that passed the checks up to opening the body.
pub struct OpenedLink {
    /// The decrypted plaintext (the canonical ShareEnvelope v3 bytes).
    pub plaintext: Vec<u8>,
    /// `header.issuer`, an Ed25519 `did:key` whose signature verified.
    pub issuer: String,
    /// `header.expiresAt`.
    pub expires_at: OffsetDateTime,
}

impl std::fmt::Debug for OpenedLink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpenedLink(..)")
    }
}

impl OpenedLink {
    /// `header.issuer == envelope.signature.signerDid == owner`.
    pub fn bind_issuer(
        &self,
        signer_did: Option<&str>,
        owner_did: &str,
    ) -> Result<(), LinkRefusal> {
        if signer_did == Some(self.issuer.as_str()) && self.issuer == owner_did {
            Ok(())
        } else {
            Err(LinkRefusal::IssuerBindingMismatch)
        }
    }

    /// The link cannot outlive the share.
    pub fn within_share_expiry(&self, share_expires_at: OffsetDateTime) -> Result<(), LinkRefusal> {
        if self.expires_at <= share_expires_at {
            Ok(())
        } else {
            Err(LinkRefusal::Expired)
        }
    }
}

/// Checks 1 to 5 on a fetched record for `link`, at `now`.
pub fn open_link_record(
    link: &ShortLink,
    fetched: &FetchedLink,
    now: OffsetDateTime,
) -> Result<OpenedLink, LinkRefusal> {
    // 1. The record header, strict; a share record, signed.
    let record = RecordHeader::parse(&fetched.record_header)?;
    if record.header_type != "share" {
        return Err(LinkRefusal::NotShare);
    }
    let Some(signature) = record.signature else {
        return Err(LinkRefusal::Unsigned);
    };

    // 2. Size, then CID(body) == bodyCid == c.
    if record.size != fetched.body.len() || fetched.body.len() > MAX_LINK_BODY_BYTES {
        return Err(LinkRefusal::SizeMismatch);
    }
    if raw_cid(&fetched.body) != record.body_cid {
        return Err(LinkRefusal::BodyCidMismatch);
    }
    if record.body_cid != link.cid {
        return Err(LinkRefusal::LinkCidMismatch);
    }

    // 3. The header signature, under the strict rule.
    let public_key = did_key_ed25519(&record.issuer).ok_or(LinkRefusal::BadSignature)?;
    let mut signed = LINK_HEADER_DOMAIN.to_vec();
    signed.extend_from_slice(&tinycloud_core::policy_capability::jcs::canonicalize(
        &Value::Object(record.header.clone()),
    ));
    if !verify_strict_prime_order(&public_key, &Sha256::digest(signed), &signature) {
        return Err(LinkRefusal::BadSignature);
    }

    // 4. The link is alive.
    if record.expires_at <= now {
        return Err(LinkRefusal::Expired);
    }

    // 5. The body opens with the key from the link.
    let plaintext = open_sealed(&fetched.body, &link.key).ok_or(LinkRefusal::BodyOpenFailed)?;
    Ok(OpenedLink {
        plaintext,
        issuer: record.issuer,
        expires_at: record.expires_at,
    })
}

/// The header and signature of an `X-Link-Record`, strictly parsed.
struct RecordHeader {
    header: Map<String, Value>,
    header_type: String,
    issuer: String,
    expires_at: OffsetDateTime,
    size: usize,
    body_cid: String,
    signature: Option<[u8; 64]>,
}

impl RecordHeader {
    /// `base64url(JSON({"header": …, "signature": …}))`: strict base64url, an
    /// object with exactly `header` and optionally `signature`, a header with
    /// exactly the nine fields of the contract and a signature with exactly
    /// `algorithm` and `value`. Every field has its closed grammar.
    fn parse(value: &str) -> Result<Self, LinkRefusal> {
        let shape = LinkRefusal::RecordShape;
        if value.len() > MAX_LINK_RECORD_HEADER_BYTES {
            return Err(shape);
        }
        let bytes = decode_strict(value).ok_or(shape)?;
        let Value::Object(mut record) =
            serde_json::from_slice::<Value>(&bytes).map_err(|_| shape)?
        else {
            return Err(shape);
        };
        let signature = record.remove("signature");
        let Some(Value::Object(header)) = record.remove("header") else {
            return Err(shape);
        };
        if !record.is_empty() {
            return Err(shape);
        }
        let signature = match signature {
            None => None,
            Some(Value::Object(signature)) => {
                if signature.len() != 2
                    || signature.get("algorithm").and_then(Value::as_str) != Some("Ed25519")
                {
                    return Err(shape);
                }
                let value = signature
                    .get("value")
                    .and_then(Value::as_str)
                    .filter(|value| value.len() == 86)
                    .and_then(decode_strict)
                    .ok_or(shape)?;
                Some(<[u8; 64]>::try_from(value).map_err(|_| shape)?)
            }
            Some(_) => return Err(shape),
        };
        if header.len() != 9 || header.get("version").and_then(Value::as_u64) != Some(1) {
            return Err(shape);
        }
        let string = |name: &str| header.get(name).and_then(Value::as_str).ok_or(shape);
        let header_type = string("type")?;
        if !matches!(header_type, "openkey-login" | "courier" | "share") {
            return Err(shape);
        }
        let issuer = string("issuer")?;
        if !is_audience(string("audience")?) {
            return Err(shape);
        }
        utc_millis(string("issuedAt")?).ok_or(shape)?;
        let expires_at = utc_millis(string("expiresAt")?).ok_or(shape)?;
        let size = header
            .get("size")
            .and_then(Value::as_u64)
            .filter(|size| *size >= 1)
            .and_then(|size| usize::try_from(size).ok())
            .ok_or(shape)?;
        let body_cid = string("bodyCid")?;
        if !is_canonical_raw_cid(body_cid) {
            return Err(shape);
        }
        let nonce = string("nonce")?;
        if nonce.len() != 22 || decode_strict(nonce).is_none_or(|nonce| nonce.len() != 16) {
            return Err(shape);
        }
        Ok(Self {
            header_type: header_type.to_owned(),
            issuer: issuer.to_owned(),
            expires_at,
            size,
            body_cid: body_cid.to_owned(),
            header,
            signature,
        })
    }
}

/// Unpadded base64url that re-encodes to the same text.
fn decode_strict(value: &str) -> Option<Vec<u8>> {
    let bytes = decode_config(value, URL_SAFE_NO_PAD).ok()?;
    (encode_config(&bytes, URL_SAFE_NO_PAD) == value).then_some(bytes)
}

fn raw_cid(bytes: &[u8]) -> String {
    Cid::new_v1(
        RAW_CODEC,
        tinycloud_auth::multihash_codetable::Code::Sha2_256.digest(bytes),
    )
    .to_string()
}

/// `bafkrei` plus 52 base32 characters: CIDv1, raw codec, sha2-256, in its
/// one canonical spelling.
fn is_canonical_raw_cid(value: &str) -> bool {
    value.len() == 59
        && value.starts_with("bafkrei")
        && Cid::try_from(value).is_ok_and(|cid| {
            cid.codec() == RAW_CODEC
                && cid.hash().code() == SHA2_256
                && cid.hash().size() == 32
                && cid.to_string() == value
        })
}

/// `https://host[:port]`, lowercase, as the header's `audience` is written.
fn is_audience(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let host = match rest.rsplit_once(':') {
        Some((host, port)) => {
            if port.is_empty() || port.len() > 5 || !port.bytes().all(|byte| byte.is_ascii_digit())
            {
                return false;
            }
            host
        }
        None => rest,
    };
    let alphanumeric = |byte: u8| byte.is_ascii_lowercase() || byte.is_ascii_digit();
    let bytes = host.as_bytes();
    !bytes.is_empty()
        && alphanumeric(bytes[0])
        && alphanumeric(bytes[bytes.len() - 1])
        && bytes
            .iter()
            .all(|byte| alphanumeric(*byte) || matches!(byte, b'.' | b'-'))
}

/// `YYYY-MM-DDTHH:mm:ss.SSSZ` that is a real date: UTC, `Z`, exactly three
/// fractional digits, and no other spelling of the instant.
pub(crate) fn utc_millis(value: &str) -> Option<OffsetDateTime> {
    let time = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let formatted = format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        time.year(),
        u8::from(time.month()),
        time.day(),
        time.hour(),
        time.minute(),
        time.second(),
        time.millisecond()
    );
    (formatted == value).then_some(time)
}

/// The 32-byte key of a canonical `did:key:z…` Ed25519 identifier.
fn did_key_ed25519(did: &str) -> Option<[u8; 32]> {
    use tinycloud_auth::ipld_core::cid::multibase::{self, Base};
    let encoded = did.strip_prefix("did:key:")?;
    let (base, bytes) = multibase::decode(encoded).ok()?;
    if base != Base::Base58Btc
        || bytes.len() != 34
        || bytes[..2] != [0xed, 0x01]
        || multibase::encode(Base::Base58Btc, &bytes) != encoded
    {
        return None;
    }
    <[u8; 32]>::try_from(&bytes[2..]).ok()
}

/// RFC 8032 strict verification plus the prime-order rule of the links
/// contract: `S < ℓ`; the encodings of `A` and `R` are canonical; `A` and `R`
/// each have order exactly ℓ (not the identity, not a small-order point, no
/// torsion component); then the equation holds.
pub(crate) fn verify_strict_prime_order(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
) -> bool {
    let prime_order = |encoded: &[u8; 32]| {
        ed25519_dalek::VerifyingKey::from_bytes(encoded).is_ok_and(|key| {
            let point = key.to_edwards();
            point.compress().to_bytes() == *encoded && !key.is_weak() && point.is_torsion_free()
        })
    };
    let r: [u8; 32] = signature[..32].try_into().expect("32 bytes");
    if !prime_order(public_key) || !prime_order(&r) {
        return false;
    }
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(public_key) else {
        return false;
    };
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(signature))
        .is_ok()
}

fn open_sealed(sealed: &[u8], key: &[u8; 32]) -> Option<Vec<u8>> {
    if sealed.len() < MIN_SEALED_BYTES || sealed[0] != SEALED_VERSION {
        return None;
    }
    let nonce = Nonce::from(
        <[u8; SEALED_NONCE_BYTES]>::try_from(&sealed[1..1 + SEALED_NONCE_BYTES])
            .expect("sealed envelope nonce length is fixed"),
    );
    Aes256Gcm::new_from_slice(key)
        .ok()?
        .decrypt(
            &nonce,
            AeadPayload {
                msg: &sealed[1 + SEALED_NONCE_BYTES..],
                aad: SEALED_AAD,
            },
        )
        .ok()
}

#[cfg(test)]
pub(crate) mod test_support;
#[cfg(test)]
mod tests;
