//! Test-only identities. `TagIdentity` is a software P-256 key that opens
//! `p256tag` stanzas the way age-plugin-yubikey does with a hardware key, so
//! tests can round-trip shares sealed to `age1tag1…` recipients.

use std::io::Read;

use age_core::format::{FileKey, Stanza};
use base64::Engine;
use hpke::Deserializable;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use zeroize::Zeroizing;

use crate::{Ark, ArkId, EscrowBundle, HolderRecipient, SharePayload};

type Kem = hpke::kem::DhP256HkdfSha256;
const P256TAG_SALT: &[u8] = b"age-encryption.org/p256tag";

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
        let enc = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode(&stanza.args[1])
            .ok()?;
        let enc = <Kem as hpke::Kem>::EncappedKey::from_bytes(&enc).ok()?;
        let opened =
            age_core::primitives::hpke_open::<Kem>(&enc, &self.0, P256TAG_SALT, &stanza.body)
                .ok()?;
        let key: [u8; 16] = opened.try_into().ok()?;
        Some(Ok(FileKey::new(Box::new(key))))
    }
}

pub(crate) fn x25519_identity() -> age::x25519::Identity {
    age::x25519::Identity::generate()
}

pub(crate) enum TestIdentity {
    Tag(TagIdentity),
    X25519(age::x25519::Identity),
}

impl TestIdentity {
    /// What `age -d -i <identity> share.age` prints.
    pub(crate) fn open(&self, armored: &str) -> Result<Zeroizing<Vec<u8>>, age::DecryptError> {
        let identity: &dyn age::Identity = match self {
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

/// An ARK and three holders: two hardware-tag keys and one X25519 key.
pub(crate) fn escrow_fixture() -> (Ark, ArkId, Vec<HolderRecipient>, Vec<TestIdentity>) {
    let (sam, sam_r) = tag_identity();
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
        TestIdentity::Tag(sam),
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
