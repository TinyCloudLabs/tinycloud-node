//! TCE1: a segmented AES-256-GCM envelope (TC-887 plan §1.2–1.3; normative
//! format in `docs/at-rest/INTERFACES.md` §4).
//!
//! ```text
//! header(64) ‖ seg_0 ‖ … ‖ seg_{n-1}       seg_i = AES-GCM(ct_i) ‖ tag16
//! K_obj   = HKDF-SHA256(ikm = DEK, salt = header.salt, info = SHA-256(ctx))
//! nonce_i = u32 BE i ‖ u8 last(i) ‖ 0^7
//! AAD     = ctx ‖ header
//! ```
//! The per-blob random salt makes K_obj unique per blob, so counter nonces
//! never repeat under one key. The index in the nonce stops reordering, the
//! last flag stops truncation, and the header (inside the AAD) binds the
//! declared length and key id.

use super::key::{DataKey, DekId};
use crate::hash::Hash;
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce, Tag,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

pub const HEADER_LEN: usize = 64;
pub const SEGMENT_LEN: usize = 1 << 16;
pub const TAG_LEN: usize = 16;

/// Every TCE generation starts `"TCE" ‖ ASCII digit g ‖ version byte g`; this
/// build reads and writes generation 1 only. See `docs/at-rest/INTERFACES.md`
/// §4 (TCE2 rule).
const FAMILY: &[u8; 3] = b"TCE";
const MAGIC: &[u8; 4] = b"TCE1";
const VERSION: u8 = 1;
const ALG_AES256GCM_HKDF_SHA256: u8 = 1;
const SEG_LOG2: u8 = 16;
const MAX_SEGMENTS: u64 = 1 << 32;
const CONTEXT_LABEL: &[u8] = b"tinycloud/at-rest/v1";
const SEGMENT_CT_LEN: u64 = (SEGMENT_LEN + TAG_LEN) as u64;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum EnvelopeError {
    /// Malformed or not a TCE header at all.
    #[error("invalid TCE1 header: {0}")]
    Header(&'static str),
    /// A well-formed TCE header (or payload encoding) of a later format
    /// generation than this build reads. Not corruption: upgrade the node.
    /// Unauthenticated (anyone who can write the bytes can produce it), so
    /// callers must fail closed: never treat it as legacy, re-seal or skip.
    #[error("unsupported at-rest format version {version}")]
    Unsupported { version: u8 },
    /// The header names a different data key than the one supplied.
    #[error("TCE1 header names a different data key")]
    KeyMismatch,
    /// Authentication failed: tampering, truncation, reordering, trailing
    /// bytes, or the blob belongs to another identity.
    #[error("TCE1 integrity check failed")]
    Integrity,
    /// More than 2^32 segments.
    #[error("plaintext too large for TCE1")]
    TooLarge,
    /// The streaming input ended before the declared length or ran past it.
    #[error("plaintext length differs from the declared length")]
    LengthMismatch,
}

/// What a ciphertext is bound to. A blob opened under any other identity
/// fails authentication.
#[derive(Clone, Copy, Debug)]
pub enum BlobIdentity<'a> {
    KvBlock {
        space: &'a str,
        content_hash: &'a Hash,
    },
    SqlCheckpoint {
        service: &'a str,
        space: &'a str,
        name: &'a str,
        checkpoint_content_hash: &'a str,
        checkpoint_size_bytes: u64,
    },
    SqlWal {
        service: &'a str,
        space: &'a str,
        name: &'a str,
        revision: i64,
        checkpoint_content_hash: &'a str,
        delta_content_hash: &'a str,
    },
}

pub(crate) fn push_lp(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
}

impl BlobIdentity<'_> {
    /// `lp(label) ‖ lp(purpose) ‖ lp(field)…`, every field length-prefixed.
    pub(crate) fn context(&self) -> Vec<u8> {
        let mut c = Vec::with_capacity(256);
        push_lp(&mut c, CONTEXT_LABEL);
        match *self {
            Self::KvBlock {
                space,
                content_hash,
            } => {
                push_lp(&mut c, b"kv-block");
                push_lp(&mut c, space.as_bytes());
                push_lp(&mut c, &Vec::<u8>::from(*content_hash));
            }
            Self::SqlCheckpoint {
                service,
                space,
                name,
                checkpoint_content_hash,
                checkpoint_size_bytes,
            } => {
                push_lp(&mut c, b"sql-checkpoint");
                push_lp(&mut c, service.as_bytes());
                push_lp(&mut c, space.as_bytes());
                push_lp(&mut c, name.as_bytes());
                push_lp(&mut c, checkpoint_content_hash.as_bytes());
                push_lp(&mut c, &checkpoint_size_bytes.to_be_bytes());
            }
            Self::SqlWal {
                service,
                space,
                name,
                revision,
                checkpoint_content_hash,
                delta_content_hash,
            } => {
                push_lp(&mut c, b"sql-wal");
                push_lp(&mut c, service.as_bytes());
                push_lp(&mut c, space.as_bytes());
                push_lp(&mut c, name.as_bytes());
                push_lp(&mut c, &revision.to_be_bytes());
                push_lp(&mut c, checkpoint_content_hash.as_bytes());
                push_lp(&mut c, delta_content_hash.as_bytes());
            }
        }
        c
    }
}

/// A parsed and validated TCE1 header.
///
/// Parsing checks structure only. The header is authenticated as part of every
/// segment's AAD, so its fields (`plaintext_len`, `dek_id`) are **unverified
/// hints until a segment has decrypted**; any one authenticated segment
/// authenticates them. A size, `Content-Length` or 416 total taken from a
/// header alone may be forged by whoever stores the bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    bytes: [u8; HEADER_LEN],
    dek_id: DekId,
    plaintext_len: u64,
}

impl Header {
    pub(crate) fn build(dek_id: DekId, plaintext_len: u64, salt: &[u8; 32]) -> Self {
        let mut b = [0u8; HEADER_LEN];
        b[0..4].copy_from_slice(MAGIC);
        b[4] = VERSION;
        b[5] = ALG_AES256GCM_HKDF_SHA256;
        b[8..12].copy_from_slice(&dek_id.get().to_be_bytes());
        b[12..20].copy_from_slice(&plaintext_len.to_be_bytes());
        b[20..52].copy_from_slice(salt);
        b[52] = SEG_LOG2;
        Self {
            bytes: b,
            dek_id,
            plaintext_len,
        }
    }

    /// Parses the first [`HEADER_LEN`] bytes of `bytes`. Every field this
    /// version does not define must be zero. A later TCE generation is
    /// [`EnvelopeError::Unsupported`], never a malformed header.
    pub fn parse(bytes: &[u8]) -> Result<Self, EnvelopeError> {
        let version = format_version(bytes)?;
        if version != VERSION {
            return Err(EnvelopeError::Unsupported { version });
        }
        let b: [u8; HEADER_LEN] = bytes
            .get(..HEADER_LEN)
            .ok_or(EnvelopeError::Header("short header"))?
            .try_into()
            .expect("64 bytes");
        debug_assert_eq!(&b[0..4], MAGIC);
        if b[5] != ALG_AES256GCM_HKDF_SHA256 {
            return Err(EnvelopeError::Header("algorithm"));
        }
        if b[6] != 0 || b[7] != 0 {
            return Err(EnvelopeError::Header("flags"));
        }
        if b[52] != SEG_LOG2 {
            return Err(EnvelopeError::Header("segment size"));
        }
        if b[53..].iter().any(|&x| x != 0) {
            return Err(EnvelopeError::Header("padding"));
        }
        let dek_id = DekId::new(u32::from_be_bytes(b[8..12].try_into().expect("4")));
        let plaintext_len = u64::from_be_bytes(b[12..20].try_into().expect("8"));
        if segment_count(plaintext_len) > MAX_SEGMENTS {
            return Err(EnvelopeError::Header("length"));
        }
        Ok(Self {
            bytes: b,
            dek_id,
            plaintext_len,
        })
    }

    pub fn as_bytes(&self) -> &[u8; HEADER_LEN] {
        &self.bytes
    }

    pub fn dek_id(&self) -> DekId {
        self.dek_id
    }

    pub fn plaintext_len(&self) -> u64 {
        self.plaintext_len
    }

    pub fn ciphertext_len(&self) -> u64 {
        ciphertext_len(self.plaintext_len).expect("validated in parse/build")
    }

    pub(crate) fn segment_count(&self) -> u64 {
        segment_count(self.plaintext_len)
    }

    fn salt(&self) -> &[u8] {
        &self.bytes[20..52]
    }
}

/// The TCE format generation from the first 5 bytes, before any
/// generation-specific parsing: `"TCE" ‖ ASCII digit g ‖ byte g`, with
/// `g` in 1..=9. Anything else is not a TCE header.
pub fn format_version(bytes: &[u8]) -> Result<u8, EnvelopeError> {
    let b = bytes
        .get(..5)
        .ok_or(EnvelopeError::Header("short header"))?;
    if &b[0..3] != FAMILY {
        return Err(EnvelopeError::Header("magic"));
    }
    match b[3] {
        d @ b'1'..=b'9' if b[4] == d - b'0' => Ok(b[4]),
        _ => Err(EnvelopeError::Header("version")),
    }
}

/// Number of segments for a plaintext length; an empty plaintext is one
/// empty segment.
pub(crate) fn segment_count(plaintext_len: u64) -> u64 {
    plaintext_len.div_ceil(SEGMENT_LEN as u64).max(1)
}

/// Plaintext length of segment `i` of `n` for a blob of `plaintext_len`.
pub(crate) fn segment_plain_len(plaintext_len: u64, i: u64) -> usize {
    let start = i * SEGMENT_LEN as u64;
    (plaintext_len - start).min(SEGMENT_LEN as u64) as usize
}

/// Absolute offset of segment `i` in the object.
pub(crate) fn segment_offset(i: u64) -> u64 {
    HEADER_LEN as u64 + i * SEGMENT_CT_LEN
}

/// Total object size for a plaintext length.
pub fn ciphertext_len(plaintext_len: u64) -> Result<u64, EnvelopeError> {
    let n = segment_count(plaintext_len);
    if n > MAX_SEGMENTS {
        return Err(EnvelopeError::TooLarge);
    }
    plaintext_len
        .checked_add(HEADER_LEN as u64 + n * TAG_LEN as u64)
        .ok_or(EnvelopeError::TooLarge)
}

/// Inverse of [`ciphertext_len`]: `None` if no plaintext length produces
/// exactly `ciphertext_len` bytes. Used to size sealed objects from a listing.
pub fn plaintext_len(ciphertext_len: u64) -> Option<u64> {
    let body = ciphertext_len.checked_sub(HEADER_LEN as u64)?;
    let n = body.div_ceil(SEGMENT_CT_LEN).max(1);
    let p = body.checked_sub(n * TAG_LEN as u64)?;
    (n <= MAX_SEGMENTS && segment_count(p) == n).then_some(p)
}

/// Per-blob AEAD state shared by the whole-buffer and streaming paths.
pub(crate) struct SegmentCipher {
    cipher: Aes256Gcm,
    aad: Vec<u8>,
    segments: u64,
}

impl SegmentCipher {
    pub(crate) fn new(key: &DataKey, id: &BlobIdentity<'_>, header: &Header) -> Self {
        let ctx = id.context();
        let info: [u8; 32] = Sha256::digest(&ctx).into();
        let mut k_obj = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(header.salt()), key.bytes())
            .expand(&info, k_obj.as_mut())
            .expect("32 bytes is a valid HKDF-SHA256 length");
        let mut aad = ctx;
        aad.extend_from_slice(header.as_bytes());
        Self {
            cipher: Aes256Gcm::new(k_obj.as_ref().into()),
            aad,
            segments: header.segment_count(),
        }
    }

    fn nonce(&self, i: u64) -> Nonce<aes_gcm::aead::consts::U12> {
        debug_assert!(i < self.segments);
        let mut n = [0u8; 12];
        n[0..4].copy_from_slice(&(i as u32).to_be_bytes());
        n[4] = u8::from(i + 1 == self.segments);
        n.into()
    }

    /// Encrypts `buf` in place as segment `i`; returns the tag.
    pub(crate) fn seal_segment(&self, i: u64, buf: &mut [u8]) -> [u8; TAG_LEN] {
        self.cipher
            .encrypt_in_place_detached(&self.nonce(i), &self.aad, buf)
            .expect("segment is below the AES-GCM length limit")
            .into()
    }

    /// Decrypts `buf` in place as segment `i`. On failure `buf` is zeroed.
    pub(crate) fn open_segment(
        &self,
        i: u64,
        buf: &mut [u8],
        tag: &[u8],
    ) -> Result<(), EnvelopeError> {
        let tag: [u8; TAG_LEN] = match tag.try_into() {
            Ok(t) if i < self.segments => t,
            _ => return Err(EnvelopeError::Integrity),
        };
        self.cipher
            .decrypt_in_place_detached(&self.nonce(i), &self.aad, buf, &Tag::from(tag))
            .map_err(|_| {
                buf.zeroize();
                EnvelopeError::Integrity
            })
    }
}

pub(crate) fn new_header(key: &DataKey, plaintext_len: u64) -> Result<Header, EnvelopeError> {
    ciphertext_len(plaintext_len)?;
    let mut salt = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    Ok(Header::build(key.id(), plaintext_len, &salt))
}

/// Seals a whole buffer in place. To avoid a reallocation and copy, pass a
/// `Vec` whose capacity is already at least `ciphertext_len(len)`.
pub fn seal(
    key: &DataKey,
    id: &BlobIdentity<'_>,
    plaintext: Vec<u8>,
) -> Result<Vec<u8>, EnvelopeError> {
    let header = new_header(key, plaintext.len() as u64)?;
    Ok(seal_into(key, id, &header, plaintext))
}

/// Test-only: a caller-chosen header reuses its salt, and so its per-blob key
/// and nonces. Production always goes through [`seal`].
#[cfg(test)]
pub(crate) fn seal_with_header(
    key: &DataKey,
    id: &BlobIdentity<'_>,
    header: &Header,
    buf: Vec<u8>,
) -> Vec<u8> {
    seal_into(key, id, header, buf)
}

fn seal_into(key: &DataKey, id: &BlobIdentity<'_>, header: &Header, mut buf: Vec<u8>) -> Vec<u8> {
    let p = header.plaintext_len();
    debug_assert_eq!(p, buf.len() as u64);
    let n = header.segment_count();
    let ct_len = header.ciphertext_len() as usize;
    buf.reserve_exact(ct_len - buf.len());
    buf.resize(ct_len, 0);
    // Move segments to their final offsets, last first: every destination is
    // at or after its source, so nothing unmoved is overwritten.
    for i in (0..n).rev() {
        let src = i as usize * SEGMENT_LEN;
        let len = segment_plain_len(p, i);
        buf.copy_within(src..src + len, segment_offset(i) as usize);
    }
    let cipher = SegmentCipher::new(key, id, header);
    for i in 0..n {
        let off = segment_offset(i) as usize;
        let len = segment_plain_len(p, i);
        let tag = cipher.seal_segment(i, &mut buf[off..off + len]);
        buf[off + len..off + len + TAG_LEN].copy_from_slice(&tag);
    }
    buf[..HEADER_LEN].copy_from_slice(header.as_bytes());
    buf
}

/// Opens a whole buffer in place. Fails unless the header names `key`, the
/// length is exact, and every segment authenticates under `id`. Never returns
/// partial plaintext.
pub fn open(
    key: &DataKey,
    id: &BlobIdentity<'_>,
    mut buf: Vec<u8>,
) -> Result<Vec<u8>, EnvelopeError> {
    let header = Header::parse(&buf)?;
    if header.dek_id() != key.id() {
        return Err(EnvelopeError::KeyMismatch);
    }
    if buf.len() as u64 != header.ciphertext_len() {
        return Err(EnvelopeError::Integrity);
    }
    let p = header.plaintext_len();
    let cipher = SegmentCipher::new(key, id, &header);
    for i in 0..header.segment_count() {
        let off = segment_offset(i) as usize;
        let len = segment_plain_len(p, i);
        let (body, rest) = buf[off..].split_at_mut(len);
        if let Err(e) = cipher.open_segment(i, body, &rest[..TAG_LEN]) {
            buf.zeroize();
            return Err(e);
        }
        buf.copy_within(off..off + len, i as usize * SEGMENT_LEN);
    }
    buf.truncate(p as usize);
    Ok(buf)
}
