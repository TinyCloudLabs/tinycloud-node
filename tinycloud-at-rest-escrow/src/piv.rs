//! `age1yubikey1…` recipients: the `piv-p256` stanza of age-plugin-yubikey.
//!
//! Released age-plugin-yubikey (0.5.x) prints and decrypts only this type;
//! native `age1tag1` support is unreleased. Encrypting to it needs no
//! YubiKey, only the public key, so the TEE can seal shares to a YubiKey
//! without the plugin binary. This mirrors the plugin's own
//! `RecipientLine::wrap_file_key` (format.rs, 0.5.1):
//!
//! ```text
//! tag        = SHA-256(pk_compressed)[..4]
//! epk        = fresh P-256 key, compressed SEC-1 (33 bytes)
//! shared     = ECDH(esk, pk).x
//! enc_key    = HKDF-SHA256(salt = epk ‖ pk_compressed, ikm = shared, info = "piv-p256")
//! body       = ChaCha20-Poly1305(enc_key, nonce = 0, file_key)        (32 bytes)
//! stanza     = "-> piv-p256 b64(tag) b64(epk)" + body
//! ```

use std::collections::HashSet;

use age_core::{
    format::{FileKey, Stanza},
    primitives::{aead_encrypt, bech32_decode, hkdf},
    secrecy::ExposeSecret,
};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use p256::{
    ecdh::EphemeralSecret,
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey,
};
use sha2::{Digest, Sha256};

pub(crate) const HRP: &str = "age1yubikey";
pub(crate) const STANZA_TAG: &str = "piv-p256";
pub(crate) const STANZA_KEY_LABEL: &[u8] = b"piv-p256";

#[derive(Clone)]
pub(crate) struct PivRecipient(PublicKey);

impl std::str::FromStr for PivRecipient {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bech32_decode(
            s,
            |_| "invalid Bech32 encoding",
            |hrp| (hrp.as_str() == HRP).then_some(()).ok_or("incorrect HRP"),
            |_, bytes| Ok(bytes.collect::<Vec<_>>()),
        )?;
        let encoded = EncodedPoint::from_bytes(bytes).map_err(|_| "invalid SEC-1 encoding")?;
        if !encoded.is_compressed() {
            return Err("not a compressed SEC-1 encoding");
        }
        PublicKey::from_encoded_point(&encoded)
            .into_option()
            .map(Self)
            .ok_or("invalid P-256 point")
    }
}

impl PivRecipient {
    fn compressed(&self) -> EncodedPoint {
        self.0.to_encoded_point(true)
    }
}

impl age::Recipient for PivRecipient {
    fn wrap_file_key(
        &self,
        file_key: &FileKey,
    ) -> Result<(Vec<Stanza>, HashSet<String>), age::EncryptError> {
        let esk = EphemeralSecret::random(&mut rand::rngs::OsRng);
        let epk = esk.public_key().to_encoded_point(true);
        let shared = esk.diffie_hellman(&self.0);
        let pk = self.compressed();

        let mut salt = Vec::with_capacity(66);
        salt.extend_from_slice(epk.as_bytes());
        salt.extend_from_slice(pk.as_bytes());
        let enc_key = hkdf(&salt, STANZA_KEY_LABEL, shared.raw_secret_bytes());
        let body = aead_encrypt(&enc_key, file_key.expose_secret());
        let tag = &Sha256::digest(pk.as_bytes())[..4];

        Ok((
            vec![Stanza {
                tag: STANZA_TAG.to_owned(),
                args: vec![
                    BASE64_STANDARD_NO_PAD.encode(tag),
                    BASE64_STANDARD_NO_PAD.encode(epk.as_bytes()),
                ],
                body,
            }],
            HashSet::new(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Read;

    use age::Identity as _;

    use super::*;
    use crate::test_support::*;

    #[test]
    fn the_released_plugins_output_opens_with_the_test_identity() {
        let decryptor =
            age::Decryptor::new_buffered(age::armor::ArmoredReader::new(PLUGIN_VECTOR.as_bytes()))
                .unwrap();
        let identity = plugin_vector_identity();
        let mut plain = Vec::new();
        decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap()
            .read_to_end(&mut plain)
            .unwrap();
        assert_eq!(plain, PLUGIN_VECTOR_MESSAGE);
        // Our recipient parser reads the plugin's recipient string.
        assert!(PLUGIN_VECTOR_RECIPIENT.parse::<PivRecipient>().is_ok());
    }

    #[test]
    fn our_stanza_has_the_plugins_shape_and_bad_shapes_are_refused() {
        let identity = plugin_vector_identity();
        let recipient: PivRecipient = PLUGIN_VECTOR_RECIPIENT.parse().unwrap();
        let file_key = FileKey::new(Box::new([7u8; 16]));
        let (stanzas, _) = age::Recipient::wrap_file_key(&recipient, &file_key).unwrap();
        let stanza = &stanzas[0];
        assert_eq!(stanza.tag, "piv-p256");
        assert_eq!((stanza.args[0].len(), stanza.args[1].len()), (6, 44));
        assert_eq!(stanza.body.len(), 32);
        let opened = identity.unwrap_stanza(stanza).unwrap().unwrap();
        assert_eq!(opened.expose_secret(), &[7u8; 16]);

        // What the plugin rejects as structurally invalid, the identity does too.
        let epk = BASE64_STANDARD_NO_PAD.decode(&stanza.args[1]).unwrap();
        let point = PublicKey::from_sec1_bytes(&epk).unwrap();
        let uncompressed = BASE64_STANDARD_NO_PAD.encode(point.to_encoded_point(false).as_bytes());
        type Mutation = Box<dyn Fn(&mut Stanza)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(move |s| s.args[1] = uncompressed.clone()),
            Box::new(|s| s.args[0].push('A')),
            Box::new(|s| {
                s.args.pop();
            }),
            Box::new(|s| s.body.push(0)),
        ];
        for mutate in mutations {
            let mut bad = Stanza {
                tag: stanza.tag.clone(),
                args: stanza.args.clone(),
                body: stanza.body.clone(),
            };
            mutate(&mut bad);
            assert!(matches!(identity.unwrap_stanza(&bad), Some(Err(_))));
        }
        // Another key's stanza is not ours.
        let (other, _) = piv_identity();
        assert!(other.unwrap_stanza(stanza).is_none());
    }
}
