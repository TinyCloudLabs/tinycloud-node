//! Test-only identities: software P-256 keys that open `piv-p256` and
//! `p256tag` stanzas exactly as age-plugin-yubikey does with the key on a
//! YubiKey, so tests can round-trip shares sealed to hardware-key recipients.

use std::io::Read;

use age_core::format::{FileKey, Stanza};
use base64::Engine;
use hpke::Deserializable;
use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use zeroize::Zeroizing;

pub(crate) use crate::RecipientPolicy;
use crate::{Ark, ArkId, EscrowBundle, HolderRecipient, SharePayload};

type Kem = hpke::kem::DhP256HkdfSha256;
const P256TAG_SALT: &[u8] = b"age-encryption.org/p256tag";

fn b64() -> base64::engine::GeneralPurpose {
    base64::engine::general_purpose::STANDARD_NO_PAD
}

pub(crate) struct TagIdentity(<Kem as hpke::Kem>::PrivateKey);

/// A fresh P-256 key and its `age1tag1…` recipient.
pub(crate) fn tag_identity() -> (TagIdentity, String) {
    let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let compressed = sk.public_key().to_encoded_point(true);
    let hrp = bech32::Hrp::parse("age1tag").unwrap();
    let recipient = age_core::primitives::bech32_encode(hrp, compressed.as_bytes());
    let hpke_sk = <Kem as hpke::Kem>::PrivateKey::from_bytes(&sk.to_bytes()).unwrap();
    (TagIdentity(hpke_sk), recipient)
}

impl age::Identity for TagIdentity {
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != "p256tag" || stanza.args.len() != 2 {
            return None;
        }
        let enc = b64().decode(&stanza.args[1]).ok()?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).ok()?;
        let opened =
            age_core::primitives::hpke_open::<Kem>(&enc, &self.0, P256TAG_SALT, &stanza.body)
                .ok()?;
        let key: [u8; 16] = opened.try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(key))))
    }
}

pub(crate) struct PivIdentity(p256::SecretKey);

/// A fresh P-256 key and its `age1yubikey1…` recipient.
pub(crate) fn piv_identity() -> (PivIdentity, String) {
    let sk = p256::SecretKey::random(&mut rand::rngs::OsRng);
    let compressed = sk.public_key().to_encoded_point(true);
    let hrp = bech32::Hrp::parse("age1yubikey").unwrap();
    // age-plugin-yubikey encodes with standard Bech32 (bech32 0.9 Variant::Bech32).
    let recipient = bech32::encode::<bech32::Bech32>(hrp, compressed.as_bytes()).unwrap();
    (PivIdentity(sk), recipient)
}

/// The released plugin's `RecipientLine::from_stanza` argument check:
/// standard unpadded base64 of exactly `N` bytes.
fn plugin_base64_arg<const N: usize>(arg: &str) -> Option<[u8; N]> {
    if arg.len() != (4 * N).div_ceil(3) {
        return None;
    }
    let mut out = [0u8; N];
    match b64().decode_slice_unchecked(arg, &mut out) {
        Ok(n) if n == N => Some(out),
        _ => None,
    }
}

impl age::Identity for PivIdentity {
    /// age-plugin-yubikey 0.5.1: `RecipientLine::from_stanza` (structure) and
    /// `YubiKey::unwrap_file_key` (math), with the YubiKey's scalar
    /// multiplication done in software. Anything the plugin treats as a
    /// structurally invalid stanza is an error here too.
    fn unwrap_stanza(&self, stanza: &Stanza) -> Option<Result<FileKey, age::DecryptError>> {
        if stanza.tag != "piv-p256" {
            return None;
        }
        let invalid = Some(Err(age::DecryptError::InvalidHeader));
        let [tag_arg, epk_arg] = &stanza.args[..] else {
            return invalid;
        };
        let (Some(tag), Some(epk_bytes)) = (
            plugin_base64_arg::<4>(tag_arg),
            plugin_base64_arg::<33>(epk_arg),
        ) else {
            return invalid;
        };
        let Ok(encoded) = p256::EncodedPoint::from_bytes(epk_bytes) else {
            return invalid;
        };
        let Some(epk) = p256::PublicKey::from_encoded_point(&encoded).into_option() else {
            return invalid;
        };
        if !encoded.is_compressed() || stanza.body.len() != 32 {
            return invalid;
        }
        let pk = self.0.public_key().to_encoded_point(true);
        if tag[..] != <sha2::Sha256 as sha2::Digest>::digest(pk.as_bytes())[..4] {
            return None;
        }
        let shared = p256::ecdh::diffie_hellman(self.0.to_nonzero_scalar(), epk.as_affine());
        let mut salt = epk_bytes.to_vec();
        salt.extend_from_slice(pk.as_bytes());
        let enc_key = age_core::primitives::hkdf(&salt, b"piv-p256", shared.raw_secret_bytes());
        Some(
            age_core::primitives::aead_decrypt(&enc_key, 16, &stanza.body)
                .ok()
                .and_then(|key| <[u8; 16]>::try_from(key).ok())
                .map(|key| FileKey::new(Box::new(key)))
                .ok_or(age::DecryptError::DecryptionFailed),
        )
    }
}

/// The checked-in vector produced by the released plugin (see
/// `tests/fixtures/NOTICE.md`).
pub(crate) const PLUGIN_VECTOR: &str = include_str!("../tests/fixtures/piv_p256_plugin_0_5_1.age");
pub(crate) const PLUGIN_VECTOR_MESSAGE: &[u8] =
    b"tinycloud age-plugin-yubikey 0.5.1 piv-p256 vector";
pub(crate) const PLUGIN_VECTOR_RECIPIENT: &str =
    "age1yubikey1qg3fps8csqk30gjdt552hf7jyjnmt753z9yhk4p8f0x5vvr5m53mju3vr5u";

pub(crate) fn plugin_vector_identity() -> PivIdentity {
    let scalar =
        hex::decode("c2d3663dcc50dd691a502185a3f4de30f4c7ef664548414eca5c6a72790f36d2").unwrap();
    PivIdentity(p256::SecretKey::from_slice(&scalar).unwrap())
}

pub(crate) fn x25519_identity() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

pub(crate) enum TestIdentity {
    Piv(PivIdentity),
    Tag(TagIdentity),
    X25519(age::x25519::Identity),
}

impl TestIdentity {
    /// What `age -d -i <identity> share.age` prints.
    pub(crate) fn open(&self, armored: &str) -> Result<Zeroizing<Vec<u8>>, age::DecryptError> {
        let identity: &dyn age::Identity = match self {
            Self::Piv(i) => i,
            Self::Tag(i) => i,
            Self::X25519(i) => i,
        };
        let decryptor =
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armored.as_bytes()))?;
        let mut reader = decryptor.decrypt(std::iter::once(identity))?;
        let mut out = Zeroizing::new(Vec::new());
        reader.read_to_end(&mut out)?;
        Ok(out)
    }
}

/// An ARK and three holders, one of each recipient kind: `age1yubikey1`,
/// `age1tag1` and X25519 (so bundles need `RecipientPolicy::AllowSoftware`).
pub(crate) fn escrow_fixture() -> (Ark, ArkId, Vec<HolderRecipient>, Vec<TestIdentity>) {
    let (sam, sam_r) = piv_identity();
    let (hunter, hunter_r) = tag_identity();
    let safe = x25519_identity();
    let safe_r = safe.to_public().to_string();
    let holders = [("sam", sam_r), ("hunter", hunter_r), ("safe", safe_r)]
        .into_iter()
        .map(|(holder, recipient)| HolderRecipient {
            holder: holder.into(),
            recipient,
        })
        .collect();
    let ids = vec![
        TestIdentity::Piv(sam),
        TestIdentity::Tag(hunter),
        TestIdentity::X25519(safe),
    ];
    (Ark::generate(), ArkId::generate(), holders, ids)
}

/// Every holder opens their own share.
pub(crate) fn open_all(bundle: &EscrowBundle, ids: &[TestIdentity]) -> Vec<SharePayload> {
    bundle
        .shares
        .iter()
        .zip(ids)
        .map(|(share, id)| {
            bundle
                .open_share(&id.open(&share.ciphertext).unwrap())
                .unwrap()
        })
        .collect()
}
