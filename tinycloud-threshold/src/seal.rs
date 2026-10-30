//! Ceremony-scoped RFC 9180 base-mode dealing envelopes. Details: TC-2220

use core::fmt;

use hpke::{
    aead::{AeadTag, ChaCha20Poly1305},
    kdf::HkdfSha256,
    kem::X25519HkdfSha256,
    Deserializable, HpkeError, Kem, OpModeR, OpModeS, Serializable,
};
use rand_core::CryptoRngCore;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    dst,
    encoding::{Decoder, Encoder},
    Error, MemberIndex,
};

type HpkeKem = X25519HkdfSha256;
type HpkeKdf = HkdfSha256;
type HpkeAead = ChaCha20Poly1305;

const VERSION: u8 = 1;
const TAG_LEN: usize = 16;
const CIPHERTEXT_CAP: usize = 65_499;
const INFO_LEN: usize = dst::DEALING.len() + 32 + 1 + 2 + 2;

/// A fresh recipient key's owned bytes, cleared on explicit zeroization or drop.
///
/// Generate independently for each ceremony. The ceremony owner retains this
/// value through the required rounds and drops it on completion or abort.
/// This type describes its own byte storage, not opaque dependency internals.
/// Details: TC-2220
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CeremonyHpkeSecretKey {
    bytes: [u8; 32],
}

impl CeremonyHpkeSecretKey {
    /// Generate a recipient key from the caller's CSPRNG. Details: TC-2220
    pub fn generate(rng: &mut impl CryptoRngCore) -> (Self, CeremonyHpkePublicKey) {
        let (secret, public) = HpkeKem::gen_keypair(rng);
        let mut owned = Self { bytes: [0; 32] };
        secret.write_exact(&mut owned.bytes);
        let mut public_bytes = [0; 32];
        public.write_exact(&mut public_bytes);
        (owned, CeremonyHpkePublicKey(public_bytes))
    }

    /// Derive this ceremony recipient's public key. Details: TC-2220
    pub(crate) fn public_key(&self) -> Result<CeremonyHpkePublicKey, Error> {
        let secret = <HpkeKem as Kem>::PrivateKey::from_bytes(&self.bytes)
            .map_err(|_| Error::InvalidHpkeKey)?;
        let public = HpkeKem::sk_to_pk(&secret);
        let mut public_bytes = [0; 32];
        public.write_exact(&mut public_bytes);
        Ok(CeremonyHpkePublicKey(public_bytes))
    }
}

impl fmt::Debug for CeremonyHpkeSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CeremonyHpkeSecretKey([REDACTED])")
    }
}

/// The exact 32 recipient-public-key bytes carried by a ceremony directory.
/// Details: TC-2220
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CeremonyHpkePublicKey([u8; 32]);

impl CeremonyHpkePublicKey {
    /// Decode exactly 32 bytes; the KEM validates agreement when used.
    /// Details: TC-2220
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        Ok(Self(bytes.try_into().map_err(|_| Error::InvalidLength)?))
    }

    /// Return the directory's exact public bytes. Details: TC-2220
    pub fn encode(&self) -> [u8; 32] {
        self.0
    }
}

/// A construction-bounded `01 || enc:32 || lp(ciphertext)` envelope.
/// Details: TC-2220
#[derive(Debug, Eq, PartialEq)]
pub struct SealedDealing {
    enc: [u8; 32],
    ciphertext: Vec<u8>,
}

impl SealedDealing {
    /// Encode an envelope whose complete length is at most 64 KiB.
    /// Details: TC-2220
    pub fn encode(&self) -> Vec<u8> {
        let mut encoder = Encoder::new();
        encoder.u8(VERSION);
        encoder.fixed(&self.enc);
        encoder.lp(&self.ciphertext);
        encoder.finish()
    }

    /// Check the version, whole-message cap, ciphertext cap and tag length
    /// before allocating; consume all input bytes. Details: TC-2220
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = Decoder::new(bytes)?;
        if decoder.u8()? != VERSION {
            return Err(Error::InvalidEncoding);
        }
        let enc = decoder.fixed()?;
        let ciphertext = decoder.lp(CIPHERTEXT_CAP)?;
        if ciphertext.len() < TAG_LEN {
            return Err(Error::InvalidLength);
        }
        decoder.finish()?;
        Ok(Self {
            enc,
            ciphertext: ciphertext.to_vec(),
        })
    }
}

/// Bind transport bytes to the caller's selected ceremony and closed round.
/// Details: TC-2220
#[derive(Clone, Copy, Debug)]
pub(crate) struct DealingContext {
    pub(crate) ceremony_digest: [u8; 32],
    pub(crate) round: u8,
    pub(crate) sender: MemberIndex,
    pub(crate) recipient: MemberIndex,
    pub(crate) commitment_hash: [u8; 32],
}

impl DealingContext {
    fn info(&self) -> [u8; INFO_LEN] {
        let sender = self.sender.get().to_be_bytes();
        let recipient = self.recipient.get().to_be_bytes();
        let fields: [&[u8]; 5] = [
            dst::DEALING,
            &self.ceremony_digest,
            core::slice::from_ref(&self.round),
            &sender,
            &recipient,
        ];
        let mut info = [0; INFO_LEN];
        for (output, byte) in info.iter_mut().zip(fields.into_iter().flatten()) {
            *output = *byte;
        }
        info
    }
}

/// Seal one dealing with fresh encapsulation randomness and a one-shot context.
///
/// The caller owns the input slice; only the internal copy is cleared here.
/// Authorization and closed-round verification belong to the ceremony API.
/// Details: TC-2220
pub(crate) fn seal_dealing(
    public: &CeremonyHpkePublicKey,
    context: &DealingContext,
    plaintext: &[u8],
    rng: &mut impl CryptoRngCore,
) -> Result<SealedDealing, Error> {
    let ciphertext_len = plaintext
        .len()
        .checked_add(TAG_LEN)
        .ok_or(Error::LimitExceeded)?;
    if ciphertext_len > CIPHERTEXT_CAP {
        return Err(Error::LimitExceeded);
    }
    let public =
        <HpkeKem as Kem>::PublicKey::from_bytes(&public.0).map_err(|_| Error::InvalidHpkeKey)?;
    let info = context.info();
    let mut buffer = Zeroizing::new(Vec::with_capacity(ciphertext_len));
    buffer.extend_from_slice(plaintext);
    let (enc, tag) = hpke::single_shot_seal_in_place_detached::<HpkeAead, HpkeKdf, HpkeKem, _>(
        &OpModeS::Base,
        &public,
        &info,
        &mut buffer,
        &context.commitment_hash,
        rng,
    )
    .map_err(dealing_error)?;
    buffer.extend_from_slice(&tag.to_bytes());
    let mut encapsulation = [0; 32];
    enc.write_exact(&mut encapsulation);
    Ok(SealedDealing {
        enc: encapsulation,
        ciphertext: core::mem::take(&mut *buffer),
    })
}

/// Open one envelope into owned storage cleared when the caller drops it.
///
/// The in-place candidate is also cleared on error. Opaque HPKE key/context
/// lifecycle behavior is outside this module's owned-storage description.
/// Details: TC-2220
pub(crate) fn open_dealing(
    secret: &CeremonyHpkeSecretKey,
    context: &DealingContext,
    sealed: &SealedDealing,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let body_len = sealed
        .ciphertext
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::InvalidLength)?;
    let (body, tag) = sealed.ciphertext.split_at(body_len);
    let tag = AeadTag::<HpkeAead>::from_bytes(tag).map_err(|_| Error::InvalidSealedDealing)?;
    let enc = <HpkeKem as Kem>::EncappedKey::from_bytes(&sealed.enc)
        .map_err(|_| Error::InvalidHpkeKey)?;
    let secret = <HpkeKem as Kem>::PrivateKey::from_bytes(&secret.bytes)
        .map_err(|_| Error::InvalidHpkeKey)?;
    let info = context.info();
    let mut plaintext = Zeroizing::new(body.to_vec());
    hpke::single_shot_open_in_place_detached::<HpkeAead, HpkeKdf, HpkeKem>(
        &OpModeR::Base,
        &secret,
        &enc,
        &info,
        &mut plaintext,
        &context.commitment_hash,
        &tag,
    )
    .map_err(dealing_error)?;
    Ok(plaintext)
}

fn dealing_error(error: HpkeError) -> Error {
    match error {
        HpkeError::ValidationError | HpkeError::EncapError | HpkeError::DecapError => {
            Error::InvalidHpkeKey
        }
        _ => Error::InvalidSealedDealing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{aead::AeadTag, Deserializable, Kem, OpModeR, OpModeS, Serializable};
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, RngCore, SeedableRng};
    use serde_json::Value;
    use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

    fn context() -> DealingContext {
        DealingContext {
            ceremony_digest: [0x11; 32],
            round: 1,
            sender: MemberIndex::new(1).unwrap(),
            recipient: MemberIndex::new(2).unwrap(),
            commitment_hash: [0x22; 32],
        }
    }

    fn bytes(value: &Value, field: &str) -> Vec<u8> {
        hex::decode(value[field].as_str().unwrap()).unwrap()
    }

    struct FixedIkm {
        bytes: [u8; 32],
        consumed: bool,
    }

    impl RngCore for FixedIkm {
        fn next_u32(&mut self) -> u32 {
            panic!("RFC test supplies exactly one 32-byte IKM")
        }

        fn next_u64(&mut self) -> u64 {
            panic!("RFC test supplies exactly one 32-byte IKM")
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            assert!(!self.consumed);
            assert_eq!(dest.len(), self.bytes.len());
            dest.copy_from_slice(&self.bytes);
            self.consumed = true;
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for FixedIkm {}

    #[test]
    fn rfc9180_appendix_a2_1_base_suite() {
        let vector: Value =
            serde_json::from_str(include_str!("../vectors/v1/hpke-rfc9180-a2-1.json")).unwrap();
        let case = &vector["cases"][0];
        let input = &case["inputs"];
        let output = &case["outputs"];
        assert_eq!(input["mode"], 0);
        assert_eq!(input["kem_id"], HpkeKem::KEM_ID);
        assert_eq!(input["kdf_id"], 1);
        assert_eq!(input["aead_id"], 3);
        let (_sk_e, pk_e) = HpkeKem::derive_keypair(&bytes(input, "ikmE"));
        let (sk_r, pk_r) = HpkeKem::derive_keypair(&bytes(input, "ikmR"));
        assert_eq!(&*pk_e.to_bytes(), bytes(output, "pkEm"));
        assert_eq!(&*pk_r.to_bytes(), bytes(output, "pkRm"));
        let mut rng = FixedIkm {
            bytes: bytes(input, "ikmE").try_into().unwrap(),
            consumed: false,
        };
        let info = bytes(input, "info");
        let (enc, mut sender) = hpke::setup_sender::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &pk_r,
            &info,
            &mut rng,
        )
        .unwrap();
        assert!(rng.consumed);
        assert_eq!(&*enc.to_bytes(), bytes(output, "enc"));
        let mut receiver =
            hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &sk_r, &enc, &info)
                .unwrap();
        let encryptions = output["encryptions"].as_array().unwrap();
        let mut sequence = 0;
        for kat in encryptions {
            let wanted = kat["sequence"].as_u64().unwrap();
            while sequence < wanted {
                let mut padding = [];
                let aad = b"advance RFC sequence";
                let tag = sender.seal_in_place_detached(&mut padding, aad).unwrap();
                receiver
                    .open_in_place_detached(&mut padding, aad, &tag)
                    .unwrap();
                sequence += 1;
            }
            let plaintext = bytes(kat, "pt");
            let aad = bytes(kat, "aad");
            let mut ciphertext = Zeroizing::new(plaintext.clone());
            let tag = sender
                .seal_in_place_detached(&mut ciphertext, &aad)
                .unwrap();
            let mut joined = ciphertext.to_vec();
            joined.extend_from_slice(&tag.to_bytes());
            assert_eq!(joined, bytes(kat, "ct"), "RFC sequence {wanted}");
            receiver
                .open_in_place_detached(&mut ciphertext, &aad, &tag)
                .unwrap();
            assert_eq!(*ciphertext, plaintext);
            sequence += 1;
        }
        for kat in output["exports"].as_array().unwrap() {
            let expected = bytes(kat, "value");
            let mut sender_value = Zeroizing::new(vec![0; expected.len()]);
            let mut receiver_value = Zeroizing::new(vec![0; expected.len()]);
            sender
                .export(&bytes(kat, "context"), &mut sender_value)
                .unwrap();
            receiver
                .export(&bytes(kat, "context"), &mut receiver_value)
                .unwrap();
            assert_eq!(*sender_value, expected);
            assert_eq!(*receiver_value, expected);
        }
        let kat = &encryptions[0];
        let mut plaintext = Zeroizing::new(bytes(kat, "pt"));
        let mut rng = FixedIkm {
            bytes: bytes(input, "ikmE").try_into().unwrap(),
            consumed: false,
        };
        let (enc, tag) = hpke::single_shot_seal_in_place_detached::<HpkeAead, HpkeKdf, HpkeKem, _>(
            &OpModeS::Base,
            &pk_r,
            &info,
            &mut plaintext,
            &bytes(kat, "aad"),
            &mut rng,
        )
        .unwrap();
        let mut joined = plaintext.to_vec();
        joined.extend_from_slice(&tag.to_bytes());
        assert_eq!(joined, bytes(kat, "ct"));
        hpke::single_shot_open_in_place_detached::<HpkeAead, HpkeKdf, HpkeKem>(
            &OpModeR::Base,
            &sk_r,
            &enc,
            &info,
            &mut plaintext,
            &bytes(kat, "aad"),
            &tag,
        )
        .unwrap();
        assert_eq!(*plaintext, bytes(kat, "pt"));
    }

    #[test]
    fn generated_recipient_keys_are_independent_and_redacted() {
        let mut rng = ChaCha20Rng::from_seed([0x31; 32]);
        let (mut secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let (other_secret, other_public) = CeremonyHpkeSecretKey::generate(&mut rng);
        assert_ne!(public, other_public);
        assert_eq!(format!("{secret:?}"), "CeremonyHpkeSecretKey([REDACTED])");
        fn zeroized_on_drop<T: Zeroize + ZeroizeOnDrop>(_: &T) {}
        zeroized_on_drop(&secret);
        let sealed = seal_dealing(&public, &context(), b"private dealing", &mut rng).unwrap();
        assert_eq!(
            open_dealing(&secret, &context(), &sealed)
                .unwrap()
                .as_slice(),
            b"private dealing"
        );
        assert!(open_dealing(&other_secret, &context(), &sealed).is_err());
        secret.zeroize();
        assert!(open_dealing(&secret, &context(), &sealed).is_err());
        let encoded = public.encode();
        assert_eq!(encoded.len(), 32);
        assert_eq!(CeremonyHpkePublicKey::decode(&encoded).unwrap(), public);
        for length in [0, 31, 33, 65537] {
            assert!(CeremonyHpkePublicKey::decode(&vec![0; length]).is_err());
        }
    }

    #[test]
    fn hpke_seal_open_wrong_context_smoke() {
        let mut rng = ChaCha20Rng::from_seed([0x32; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let plaintext = b"two scalar values for a ceremony recipient";
        let sealed = seal_dealing(&public, &ctx, plaintext, &mut rng).unwrap();
        let wire = sealed.encode();
        let decoded = SealedDealing::decode(&wire).unwrap();
        let opened: Zeroizing<Vec<u8>> = open_dealing(&secret, &ctx, &decoded).unwrap();
        assert_eq!(opened.as_slice(), plaintext);
        let mut wrong = ctx;
        wrong.ceremony_digest[0] ^= 1;
        assert!(open_dealing(&secret, &wrong, &decoded).is_err());
        println!("seal/open: original plaintext recovered; canonical envelope: {} bytes; changed ceremony: rejected", wire.len());
    }

    #[test]
    fn every_context_field_and_recipient_key_is_bound() {
        let mut rng = ChaCha20Rng::from_seed([0x33; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let (other_secret, _) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let sealed = seal_dealing(&public, &ctx, b"dealing", &mut rng).unwrap();
        let mut ceremony = ctx;
        ceremony.ceremony_digest[0] ^= 1;
        let mut round = ctx;
        round.round = 2;
        let mut sender = ctx;
        sender.sender = MemberIndex::new(3).unwrap();
        let mut recipient = ctx;
        recipient.recipient = MemberIndex::new(3).unwrap();
        let mut commitments = ctx;
        commitments.commitment_hash[0] ^= 1;
        for changed in [ceremony, round, sender, recipient, commitments] {
            assert!(
                open_dealing(&secret, &changed, &sealed).is_err(),
                "{changed:?}"
            );
        }
        assert!(open_dealing(&other_secret, &ctx, &sealed).is_err());
    }

    #[test]
    fn encapsulation_ciphertext_and_tag_mutations_are_rejected() {
        let mut rng = ChaCha20Rng::from_seed([0x34; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let sealed = seal_dealing(&public, &ctx, b"dealing", &mut rng).unwrap();
        let wire = sealed.encode();
        for offset in [1, 32, 37, wire.len() - 1] {
            let mut changed = wire.clone();
            changed[offset] ^= 1;
            let changed = SealedDealing::decode(&changed).unwrap();
            assert!(open_dealing(&secret, &ctx, &changed).is_err());
        }
        let again = seal_dealing(&public, &ctx, b"dealing", &mut rng).unwrap();
        assert_ne!(sealed.enc, again.enc);
    }

    #[test]
    fn low_order_recipient_and_encapsulation_fail() {
        let mut rng = ChaCha20Rng::from_seed([0x35; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let sealed = seal_dealing(&public, &ctx, b"dealing", &mut rng).unwrap();
        let mut one = [0; 32];
        one[0] = 1;
        let mut p_minus_one = [0xff; 32];
        p_minus_one[0] = 0xec;
        p_minus_one[31] = 0x7f;
        for low_order in [[0; 32], one, p_minus_one] {
            let key = CeremonyHpkePublicKey::decode(&low_order).unwrap();
            assert!(seal_dealing(&key, &ctx, b"dealing", &mut rng).is_err());
            let mut wire = sealed.encode();
            wire[1..33].copy_from_slice(&low_order);
            let changed = SealedDealing::decode(&wire).unwrap();
            assert!(open_dealing(&secret, &ctx, &changed).is_err());
        }
    }

    #[test]
    fn envelope_has_exact_layout_and_canonical_lengths() {
        let mut rng = ChaCha20Rng::from_seed([0x36; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let sealed = seal_dealing(&public, &ctx, b"dealing", &mut rng).unwrap();
        let wire = sealed.encode();
        assert_eq!(wire[0], 1);
        assert_eq!(&wire[1..33], sealed.enc);
        assert_eq!(&wire[33..37], &(7u32 + 16).to_be_bytes());
        assert_eq!(&wire[37..], sealed.ciphertext);
        assert_eq!(SealedDealing::decode(&wire).unwrap().encode(), wire);
        for length in 0..wire.len() {
            assert!(SealedDealing::decode(&wire[..length]).is_err());
        }
        let mut trailing = wire.clone();
        trailing.push(0);
        assert!(matches!(
            SealedDealing::decode(&trailing),
            Err(Error::InvalidEncoding)
        ));
        let mut version = wire.clone();
        version[0] = 2;
        assert!(matches!(
            SealedDealing::decode(&version),
            Err(Error::InvalidEncoding)
        ));
        let mut oversized_length = wire.clone();
        oversized_length[33..37].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(matches!(
            SealedDealing::decode(&oversized_length),
            Err(Error::LimitExceeded)
        ));
        let mut short_tag = wire[..37].to_vec();
        short_tag[33..37].copy_from_slice(&15u32.to_be_bytes());
        short_tag.extend_from_slice(&[0; 15]);
        assert!(matches!(
            SealedDealing::decode(&short_tag),
            Err(Error::InvalidLength)
        ));
        for size in [0, 65_483] {
            let plaintext = Zeroizing::new(vec![0x5a; size]);
            let sealed = seal_dealing(&public, &ctx, &plaintext, &mut rng).unwrap();
            assert_eq!(sealed.encode().len(), size + 53);
            assert_eq!(open_dealing(&secret, &ctx, &sealed).unwrap(), plaintext);
        }
        assert!(matches!(
            seal_dealing(&public, &ctx, &vec![0; 65_484], &mut rng),
            Err(Error::LimitExceeded)
        ));
        assert!(matches!(
            SealedDealing::decode(&vec![0; 65_537]),
            Err(Error::LimitExceeded)
        ));
    }

    #[test]
    fn deterministic_binding_matches_direct_rfc_api() {
        let mut rng = ChaCha20Rng::from_seed([0x37; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let (other_secret, other_public) = CeremonyHpkeSecretKey::generate(&mut rng);
        let ctx = context();
        let mut direct_info = b"TC-THRESHOLD-V1-DEALING".to_vec();
        direct_info.extend_from_slice(&[0x11; 32]);
        direct_info.extend_from_slice(&[1, 0, 1, 0, 2]);
        let mut rng = ChaCha20Rng::from_seed([0x38; 32]);
        let sealed = seal_dealing(&public, &ctx, b"bound dealing", &mut rng).unwrap();
        let pk = <HpkeKem as Kem>::PublicKey::from_bytes(&public.encode()).unwrap();
        let enc = <HpkeKem as Kem>::EncappedKey::from_bytes(&sealed.enc).unwrap();
        let ciphertext = &sealed.ciphertext;
        let (body, tag) = ciphertext.split_at(ciphertext.len() - 16);
        let tag = AeadTag::<HpkeAead>::from_bytes(tag).unwrap();
        let mut direct = Zeroizing::new(b"bound dealing".to_vec());
        let mut direct_rng = ChaCha20Rng::from_seed([0x38; 32]);
        let (expected_enc, expected_tag) =
            hpke::single_shot_seal_in_place_detached::<HpkeAead, HpkeKdf, HpkeKem, _>(
                &OpModeS::Base,
                &pk,
                &direct_info,
                &mut direct,
                &[0x22; 32],
                &mut direct_rng,
            )
            .unwrap();
        assert_eq!(&*expected_enc.to_bytes(), sealed.enc);
        assert_eq!(expected_tag.to_bytes(), tag.to_bytes());
        assert_eq!(direct.as_slice(), body);
        let mut other_ctx = ctx;
        other_ctx.recipient = MemberIndex::new(3).unwrap();
        let mut rng = ChaCha20Rng::from_seed([0x38; 32]);
        let for_other =
            seal_dealing(&other_public, &other_ctx, b"bound dealing", &mut rng).unwrap();
        assert_ne!(sealed.ciphertext, for_other.ciphertext);
        assert_eq!(
            open_dealing(&other_secret, &other_ctx, &for_other)
                .unwrap()
                .as_slice(),
            b"bound dealing"
        );
        assert!(open_dealing(&secret, &ctx, &for_other).is_err());
        let mut other_ceremony = ctx;
        other_ceremony.ceremony_digest[0] ^= 1;
        let mut rng = ChaCha20Rng::from_seed([0x38; 32]);
        let other = seal_dealing(&public, &other_ceremony, b"bound dealing", &mut rng).unwrap();
        assert_ne!(sealed.ciphertext, other.ciphertext);
        assert!(open_dealing(&secret, &ctx, &other).is_err());
        assert_eq!(&*enc.to_bytes(), sealed.enc);
    }

    proptest::proptest! {
        #[test]
        fn arbitrary_envelopes_are_rejected_or_canonical(
            wire in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..70_000)
        ) {
            if let Ok(sealed) = SealedDealing::decode(&wire) {
                proptest::prop_assert_eq!(sealed.encode(), wire);
            }
        }

        #[test]
        fn structured_envelopes_preserve_all_public_bytes(
            enc in proptest::prelude::any::<[u8; 32]>(),
            ciphertext in proptest::collection::vec(proptest::prelude::any::<u8>(), 16..256)
        ) {
            let mut wire = vec![1];
            wire.extend_from_slice(&enc);
            wire.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
            wire.extend_from_slice(&ciphertext);
            let decoded = SealedDealing::decode(&wire).unwrap();
            proptest::prop_assert_eq!(decoded.enc, enc);
            proptest::prop_assert_eq!(&decoded.ciphertext, &ciphertext);
            proptest::prop_assert_eq!(decoded.encode(), wire);
        }
    }

    #[test]
    fn secret_public_key_matches_generated_recipient() {
        let mut rng = ChaCha20Rng::from_seed([0x39; 32]);
        let (secret, public) = CeremonyHpkeSecretKey::generate(&mut rng);
        assert_eq!(secret.public_key(), Ok(public));
    }
}
