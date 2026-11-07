//! One holder's Shamir share and the binary form sealed inside its age file.

use zeroize::Zeroizing;

use crate::{lp, sha256, ArkId, Digest32, EscrowError, HOLDERS};

const MAGIC: &[u8; 4] = b"TCS1";
/// x-coordinate byte followed by one y byte per ARK byte.
pub(crate) const SHARE_LEN: usize = 33;
/// `"TCS1" ‖ ark_id(16) ‖ generation u32 BE ‖ index u8 ‖ share(33)`.
pub(crate) const PAYLOAD_LEN: usize = 4 + 16 + 4 + 1 + SHARE_LEN;
const COMMIT_DOMAIN: &[u8] = b"tinycloud/at-rest/escrow-share-commit/v1";

/// A decrypted share. The share bytes are zeroized on drop and never printed.
#[derive(Clone)]
pub struct SharePayload {
    pub ark_id: ArkId,
    pub generation: u32,
    /// 1..=3; equals the Shamir x-coordinate in `share[0]`.
    pub index: u8,
    pub(crate) share: Zeroizing<[u8; SHARE_LEN]>,
}

impl std::fmt::Debug for SharePayload {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharePayload")
            .field("ark_id", &self.ark_id)
            .field("generation", &self.generation)
            .field("index", &self.index)
            .finish_non_exhaustive()
    }
}

impl SharePayload {
    pub(crate) fn new(ark_id: ArkId, generation: u32, share: &[u8]) -> Result<Self, EscrowError> {
        let share: [u8; SHARE_LEN] = share.try_into().map_err(|_| EscrowError::Shamir)?;
        let payload = Self {
            ark_id,
            generation,
            index: share[0],
            share: Zeroizing::new(share),
        };
        payload.check_index()?;
        Ok(payload)
    }

    fn check_index(&self) -> Result<(), EscrowError> {
        if self.index == 0 || self.index > HOLDERS || self.share[0] != self.index {
            return Err(EscrowError::ShareFormat);
        }
        Ok(())
    }

    /// The bytes sealed to the holder. Zeroized on drop.
    pub fn encode(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::with_capacity(PAYLOAD_LEN));
        out.extend_from_slice(MAGIC);
        out.extend_from_slice(&self.ark_id.0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        out.push(self.index);
        out.extend_from_slice(self.share.as_slice());
        out
    }

    /// Strict inverse of [`encode`](Self::encode): exact length, known magic,
    /// index in 1..=3 and equal to the share's x-coordinate.
    pub fn decode(bytes: &[u8]) -> Result<Self, EscrowError> {
        if bytes.len() != PAYLOAD_LEN || &bytes[..4] != MAGIC {
            return Err(EscrowError::ShareFormat);
        }
        let ark_id = ArkId(bytes[4..20].try_into().expect("16 bytes"));
        let generation = u32::from_be_bytes(bytes[20..24].try_into().expect("4 bytes"));
        let index = bytes[24];
        let mut share = Zeroizing::new([0u8; SHARE_LEN]);
        share.copy_from_slice(&bytes[25..]);
        let payload = Self {
            ark_id,
            generation,
            index,
            share,
        };
        payload.check_index()?;
        Ok(payload)
    }

    /// `SHA-256(lp(domain) ‖ ark_id ‖ generation ‖ index ‖ lp(share))`.
    ///
    /// The share is 32 uniformly random bytes plus its x-coordinate, so the
    /// commitment can be public: it lets anyone holding the bundle check a
    /// single share without a second one, and lets the TEE reject junk
    /// before it occupies a slot.
    pub fn commitment(&self) -> Digest32 {
        let mut pre = Vec::with_capacity(96);
        lp(&mut pre, COMMIT_DOMAIN);
        pre.extend_from_slice(&self.ark_id.0);
        pre.extend_from_slice(&self.generation.to_be_bytes());
        pre.push(self.index);
        lp(&mut pre, self.share.as_slice());
        let digest = Digest32(sha256(&pre));
        zeroize::Zeroize::zeroize(&mut pre);
        digest
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(index: u8) -> SharePayload {
        let mut share = [9u8; SHARE_LEN];
        share[0] = index;
        SharePayload::new(ArkId([1; 16]), 1, &share).unwrap()
    }

    #[test]
    fn decode_rejects_wrong_length_magic_and_index() {
        let good = sample(2).encode();
        assert_eq!(SharePayload::decode(&good).unwrap().index, 2);
        assert!(SharePayload::decode(&good[..PAYLOAD_LEN - 1]).is_err());
        let mut extra = good.to_vec();
        extra.push(0);
        assert!(SharePayload::decode(&extra).is_err());
        let mut bad_magic = good.to_vec();
        bad_magic[0] = b'X';
        assert!(SharePayload::decode(&bad_magic).is_err());
        for index in [0u8, 4, 255] {
            let mut bad = good.to_vec();
            bad[24] = index;
            bad[25] = index;
            assert!(SharePayload::decode(&bad).is_err(), "index {index}");
        }
        // Index byte disagreeing with the Shamir x-coordinate.
        let mut skew = good.to_vec();
        skew[24] = 3;
        assert!(SharePayload::decode(&skew).is_err());
    }

    #[test]
    fn commitment_binds_every_field() {
        let base = sample(1);
        let c = base.commitment();
        let mut other_id = base.clone();
        other_id.ark_id = ArkId([2; 16]);
        let mut other_gen = base.clone();
        other_gen.generation = 2;
        let mut other_byte = base.clone();
        other_byte.share[32] ^= 1;
        for changed in [other_id, other_gen, other_byte] {
            assert_ne!(changed.commitment(), c);
        }
    }
}
