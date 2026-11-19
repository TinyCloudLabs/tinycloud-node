//! Frozen domains from plan §3.3 and RFC 9380 §5 SHA-256 XMD.

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::curve::Scalar;
#[cfg(test)]
use crate::Error;

pub(crate) const H1: &[u8] = b"TC-THRESHOLD-V1-IBE-ID_BLS12381G1_XMD:SHA-256_SSWU_RO_";
pub(crate) const PEDERSEN_H: &[u8] = b"TC-THRESHOLD-V1-PEDERSEN-H_BLS12381G2_XMD:SHA-256_SSWU_RO_";
pub(crate) const H2: &[u8] = b"TC-THRESHOLD-V1-IBE-H2";
pub(crate) const H3: &[u8] = b"TC-THRESHOLD-V1-IBE-H3";
pub(crate) const H4: &[u8] = b"TC-THRESHOLD-V1-IBE-H4";
pub(crate) const IDENTITY_PREFIX: &[u8] = b"TC-THRESHOLD-V1-IBE-ID-ENC";
pub(crate) const KEY_CONTEXT: &[u8] = b"TC-THRESHOLD-V1-KEY-CONTEXT";
pub(crate) const DECRYPT_REQUEST: &[u8] = b"TC-THRESHOLD-V1-DECRYPT-REQUEST";
pub(crate) const DECRYPT_SHARE: &[u8] = b"TC-THRESHOLD-V1-DECRYPT-SHARE";
pub(crate) const COMMITMENTS: &[u8] = b"TC-THRESHOLD-V1-COMMITMENTS";
pub(crate) const CEREMONY_AUTH: &[u8] = b"TC-THRESHOLD-V1-CEREMONY-AUTH";
pub(crate) const CEREMONY_MSG: &[u8] = b"TC-THRESHOLD-V1-CEREMONY-MSG";
pub(crate) const ROUND_CLOSE: &[u8] = b"TC-THRESHOLD-V1-ROUND-CLOSE";
pub(crate) const TRANSCRIPT: &[u8] = b"TC-THRESHOLD-V1-TRANSCRIPT";
pub(crate) const NETWORK_CERT: &[u8] = b"TC-THRESHOLD-V1-NETWORK-CERT";
pub(crate) const CERT_STATEMENT: &[u8] = b"TC-THRESHOLD-V1-CERT-STATEMENT";
pub(crate) const READY: &[u8] = b"TC-THRESHOLD-V1-READY";
pub(crate) const ACTIVATE: &[u8] = b"TC-THRESHOLD-V1-ACTIVATE";
pub(crate) const DEALING: &[u8] = b"TC-THRESHOLD-V1-DEALING";

/// The complete frozen domain table, including later ceremony/certificate uses.
pub const DOMAINS: &[&[u8]] = &[
    H1,
    PEDERSEN_H,
    H2,
    H3,
    H4,
    IDENTITY_PREFIX,
    KEY_CONTEXT,
    DECRYPT_REQUEST,
    DECRYPT_SHARE,
    COMMITMENTS,
    CEREMONY_AUTH,
    CEREMONY_MSG,
    ROUND_CLOSE,
    TRANSCRIPT,
    NETWORK_CERT,
    CERT_STATEMENT,
    READY,
    ACTIVATE,
    DEALING,
];

/// Callers use the bounded, frozen tags above, never message-sized domains.
pub(crate) fn tagged_hash(tag: &[u8], body: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update((tag.len() as u32).to_be_bytes());
    hash.update(tag);
    hash.update(body);
    hash.finalize().into()
}

/// RFC 9380 §§5.3.1,5.3.3. SHA-256 limits ell to 255 blocks.
#[cfg(test)]
pub(crate) fn expand_xmd<const N: usize>(msg: &[u8], dst: &[u8]) -> Result<[u8; N], Error> {
    if N == 0 || N > 8160 {
        return Err(Error::InvalidLength);
    }
    let length = u16::try_from(N)
        .map_err(|_| Error::InvalidLength)?
        .to_be_bytes();
    let mut shortened = [0; 32];
    let dst = if dst.len() > 255 {
        let mut hash = Sha256::new();
        hash.update(b"H2C-OVERSIZE-DST-");
        hash.update(dst);
        shortened.copy_from_slice(&hash.finalize());
        shortened.as_slice()
    } else {
        dst
    };
    let dst_len = u8::try_from(dst.len()).map_err(|_| Error::InvalidLength)?;
    Ok(xmd(msg, dst, length, dst_len))
}

/// Internal callers supply statically valid lengths. Keeping this infallible
/// avoids impossible-error fallbacks in the frozen H2/H3/H4 functions.
fn xmd<const N: usize>(msg: &[u8], dst: &[u8], length: [u8; 2], dst_len: u8) -> [u8; N] {
    let mut hash = Sha256::new();
    hash.update([0; 64]);
    hash.update(msg);
    hash.update(length);
    hash.update([0]);
    hash.update(dst);
    hash.update([dst_len]);
    let mut digest = hash.finalize();
    let mut b0 = Zeroizing::new([0; 32]);
    b0.copy_from_slice(&digest);
    for byte in digest.iter_mut() {
        byte.zeroize();
    }

    let mut previous = Zeroizing::new([0; 32]);
    let mut input = Zeroizing::new([0; 32]);
    let mut out = [0; N];
    for (chunk, counter) in out.chunks_mut(32).zip(1u8..=255) {
        if counter == 1 {
            input.copy_from_slice(b0.as_ref());
        } else {
            for ((dst, a), b) in input.iter_mut().zip(b0.iter()).zip(previous.iter()) {
                *dst = a ^ b;
            }
        }
        let mut hash = Sha256::new();
        hash.update(input.as_ref());
        hash.update([counter]);
        hash.update(dst);
        hash.update([dst_len]);
        let mut digest = hash.finalize();
        previous.copy_from_slice(&digest);
        for byte in digest.iter_mut() {
            byte.zeroize();
        }
        for (dst, source) in chunk.iter_mut().zip(previous.iter()) {
            *dst = *source;
        }
    }
    out
}

pub(crate) fn h2(gt: &[u8; 576]) -> [u8; 32] {
    xmd(gt, H2, [0, 32], 22)
}

/// RFC 9380 hash_to_field with count=1, m=1, L=48, modulus r, NOT p.
pub(crate) fn h3(input: &[u8; 64]) -> Scalar {
    let uniform = Zeroizing::new(xmd::<48>(input, H3, [0, 48], 22));
    Scalar::reduce(uniform.as_ref())
}

pub(crate) fn h4(sigma: &[u8; 32]) -> [u8; 32] {
    xmd(sigma, H4, [0, 32], 22)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc9380_appendix_k1_expand_xmd_sha256() {
        let f: serde_json::Value =
            serde_json::from_str(include_str!("../vectors/v1/rfc9380-k1.json")).unwrap();
        for case in f["cases"].as_array().unwrap() {
            let msg = case["inputs"]["msg"].as_str().unwrap().as_bytes();
            let dst = f["dst"].as_str().unwrap().as_bytes();
            let expected = case["outputs"]["uniform_bytes"].as_str().unwrap();
            match case["inputs"]["len"].as_u64().unwrap() {
                32 => assert_eq!(hex::encode(expand_xmd::<32>(msg, dst).unwrap()), expected),
                128 => assert_eq!(hex::encode(expand_xmd::<128>(msg, dst).unwrap()), expected),
                _ => panic!("unexpected RFC length"),
            }
        }
    }

    #[test]
    fn h3_modulus_r_known_answer() {
        // RFC 9380 §5 with L=48 and r from plan §3.2. KAT calculated
        // directly with Python hashlib and integer remainder, not a curve library.
        assert_eq!(
            hex::encode(h3(&[0; 64]).to_bytes()),
            "3947ae6f5d03f2e986b43b61590c8024201cb3f932154b5f2565f1ccd3deb325"
        );
        assert_eq!(
            hex::encode(h2(&[0; 576])),
            "198dcd319e3485eb604d6707177332b2ea6781f77428676161adb0b37baea90f"
        );
        assert_eq!(
            hex::encode(h4(&[0; 32])),
            "dd63b23305e0799f7e1d9977599d82a04a995888f4414d9aac22e489cc09a36d"
        );
        assert_eq!(
            hex::encode(tagged_hash(b"tag", b"body")),
            "55e024df6096cd1ffeecb9075b33ac7e902bedc07ef0bad9886bbd4375811459"
        );
    }

    #[test]
    fn domains_and_tagged_hashes_are_distinct() {
        let tags = [
            H1,
            PEDERSEN_H,
            H2,
            H3,
            H4,
            IDENTITY_PREFIX,
            KEY_CONTEXT,
            DECRYPT_REQUEST,
            DECRYPT_SHARE,
            COMMITMENTS,
            CEREMONY_AUTH,
            CEREMONY_MSG,
            ROUND_CLOSE,
            TRANSCRIPT,
            NETWORK_CERT,
            CERT_STATEMENT,
            READY,
            ACTIVATE,
            DEALING,
        ];
        for (i, tag) in tags.iter().enumerate() {
            for other in tags.iter().skip(i + 1) {
                assert_ne!(tag, other);
                assert_ne!(tagged_hash(tag, b"body"), tagged_hash(other, b"body"));
            }
        }
        assert_ne!(tagged_hash(b"a", b"bc"), tagged_hash(b"ab", b"c"));
        assert_eq!(h2(&[0; 576]), expand_xmd::<32>(&[0; 576], H2).unwrap());
        assert_eq!(h4(&[0; 32]), expand_xmd::<32>(&[0; 32], H4).unwrap());
    }

    #[test]
    fn xmd_bounds_and_oversize_dst() {
        assert!(expand_xmd::<0>(b"", H1).is_err());
        assert!(expand_xmd::<8161>(b"", H1).is_err());
        assert!(expand_xmd::<8160>(b"", H1).is_ok());
        let dst = [42u8; 256];
        let mut h = Sha256::new();
        h.update(b"H2C-OVERSIZE-DST-");
        h.update(dst);
        let shortened = h.finalize();
        assert_eq!(
            expand_xmd::<48>(b"abc", &dst).unwrap(),
            expand_xmd::<48>(b"abc", &shortened).unwrap()
        );
        assert_eq!(expand_xmd::<1>(b"abc", H1).unwrap().len(), 1);
    }
}
