//! The at-rest key hierarchy below the node root R (TC-887 plan §1.1):
//!
//! ```text
//! W     = HKDF-SHA256(R, info "tinycloud/at-rest/wrap/v1")        never stored
//! ARK_g = 32 random bytes, sealed: nonce ‖ AES-256-GCM(W, ARK_g, AAD seal)
//! chain = nonce ‖ AES-256-GCM(HKDF(ARK_{g+1}, "…/ark-chain/v1"), ARK_g, AAD chain)
//! KEK_g = HKDF-SHA256(ARK_g, info "tinycloud/at-rest/kek/v1")
//! NK    = HKDF-SHA256(ARK_1, info "tinycloud/at-rest/object-names/v1")
//! DEK   = 32 random bytes per (space, dek_id): nonce ‖ AES-256-GCM(KEK_g, DEK, AAD dek)
//! ```
//!
//! Every AAD starts with a length-prefixed domain string; variable fields are
//! length-prefixed (`lp(x) = u32 BE len ‖ x`). Nonces are random: each key
//! seals a handful of values, far below AES-GCM's random-nonce bound.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use tinycloud_at_rest_escrow::{Ark, ArkId};
use zeroize::Zeroizing;

use super::{DataKey, DekId, ObjectNameKey};

/// The label of the current W. A different label means a different W; rows
/// record which one sealed them.
pub const W_LABEL: &str = "tinycloud/at-rest/wrap/v1";
const KEK_INFO: &[u8] = b"tinycloud/at-rest/kek/v1";
const NK_INFO: &[u8] = b"tinycloud/at-rest/object-names/v1";
const CHAIN_INFO: &[u8] = b"tinycloud/at-rest/ark-chain/v1";
const SEAL_DOMAIN: &[u8] = b"tinycloud/at-rest/ark-seal/v1";
const CHAIN_DOMAIN: &[u8] = b"tinycloud/at-rest/ark-chain-aad/v1";
const DEK_DOMAIN: &[u8] = b"tinycloud/at-rest/dek/v1";
const NONCE_LEN: usize = 12;

/// An AEAD open failed: wrong key, wrong binding, or tampered bytes.
#[derive(Debug, thiserror::Error)]
#[error("at-rest key material does not authenticate")]
pub struct Unauthentic;

fn lp(out: &mut Vec<u8>, bytes: &[u8]) {
    let len = u32::try_from(bytes.len()).expect("field shorter than 4 GiB");
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
}

fn hkdf32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out.as_mut())
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

fn seal(key: &[u8; 32], aad: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .expect("AES-GCM encryption of 32 bytes cannot fail");
    let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

fn open32(key: &[u8; 32], aad: &[u8], sealed: &[u8]) -> Result<Zeroizing<[u8; 32]>, Unauthentic> {
    if sealed.len() != NONCE_LEN + 32 + 16 {
        return Err(Unauthentic);
    }
    let cipher = Aes256Gcm::new_from_slice(key).expect("32-byte key");
    let (nonce, ct) = sealed.split_at(NONCE_LEN);
    let nonce: [u8; NONCE_LEN] = nonce.try_into().expect("length checked above");
    let plain = Zeroizing::new(
        cipher
            .decrypt(&Nonce::from(nonce), Payload { msg: ct, aad })
            .map_err(|_| Unauthentic)?,
    );
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&plain);
    Ok(out)
}

/// W, derived from the node root. Never stored.
pub struct WrapKey(Zeroizing<[u8; 32]>);

impl WrapKey {
    pub fn derive(root: &[u8]) -> Self {
        Self(hkdf32(root, W_LABEL.as_bytes()))
    }
}

fn seal_aad(ark_id: &ArkId, generation: u32, w_label: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    lp(&mut aad, SEAL_DOMAIN);
    lp(&mut aad, &ark_id.0);
    aad.extend_from_slice(&generation.to_be_bytes());
    lp(&mut aad, w_label.as_bytes());
    aad
}

pub fn seal_ark(w: &WrapKey, ark: &Ark, ark_id: &ArkId, generation: u32) -> Vec<u8> {
    seal(&w.0, &seal_aad(ark_id, generation, W_LABEL), ark.expose())
}

pub fn open_ark(
    w: &WrapKey,
    sealed: &[u8],
    ark_id: &ArkId,
    generation: u32,
    w_label: &str,
) -> Result<Ark, Unauthentic> {
    if w_label != W_LABEL {
        return Err(Unauthentic);
    }
    open32(&w.0, &seal_aad(ark_id, generation, w_label), sealed).map(Ark::from_zeroizing)
}

fn chain_aad(older_id: &ArkId, older_generation: u32, newer_id: &ArkId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(96);
    lp(&mut aad, CHAIN_DOMAIN);
    lp(&mut aad, &older_id.0);
    aad.extend_from_slice(&older_generation.to_be_bytes());
    lp(&mut aad, &newer_id.0);
    aad
}

/// Seal generation g's ARK under generation g+1's chain key, so escrowing
/// the newest ARK recovers every older one.
pub fn chain_ark(
    newer: &Ark,
    newer_id: &ArkId,
    older: &Ark,
    older_id: &ArkId,
    older_generation: u32,
) -> Vec<u8> {
    let key = hkdf32(newer.expose(), CHAIN_INFO);
    seal(
        &key,
        &chain_aad(older_id, older_generation, newer_id),
        older.expose(),
    )
}

pub fn open_chain(
    newer: &Ark,
    newer_id: &ArkId,
    chain: &[u8],
    older_id: &ArkId,
    older_generation: u32,
) -> Result<Ark, Unauthentic> {
    let key = hkdf32(newer.expose(), CHAIN_INFO);
    open32(
        &key,
        &chain_aad(older_id, older_generation, newer_id),
        chain,
    )
    .map(Ark::from_zeroizing)
}

/// KEK_g. Wraps the DEKs created while generation g was current.
pub struct Kek(Zeroizing<[u8; 32]>);

impl Kek {
    pub fn derive(ark: &Ark) -> Self {
        Self(hkdf32(ark.expose(), KEK_INFO))
    }
}

/// NK from ARK generation 1; constant for the deployment.
pub fn object_name_key(ark_1: &Ark) -> ObjectNameKey {
    let nk = hkdf32(ark_1.expose(), NK_INFO);
    ObjectNameKey::new(*nk)
}

fn dek_aad(space: &str, dek_id: DekId, generation: u32, ark_id: &ArkId) -> Vec<u8> {
    let mut aad = Vec::with_capacity(64 + space.len());
    lp(&mut aad, DEK_DOMAIN);
    lp(&mut aad, space.as_bytes());
    aad.extend_from_slice(&dek_id.get().to_be_bytes());
    aad.extend_from_slice(&generation.to_be_bytes());
    lp(&mut aad, &ark_id.0);
    aad
}

/// A fresh random DEK, wrapped. Returns the wrapped bytes and the key.
pub fn new_dek(
    kek: &Kek,
    space: &str,
    dek_id: DekId,
    generation: u32,
    ark_id: &ArkId,
) -> (Vec<u8>, DataKey) {
    let mut bytes = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(bytes.as_mut());
    let wrapped = seal(
        &kek.0,
        &dek_aad(space, dek_id, generation, ark_id),
        bytes.as_ref(),
    );
    (wrapped, DataKey::new(dek_id, *bytes))
}

pub fn unwrap_dek(
    kek: &Kek,
    wrapped: &[u8],
    space: &str,
    dek_id: DekId,
    generation: u32,
    ark_id: &ArkId,
) -> Result<DataKey, Unauthentic> {
    let bytes = open32(&kek.0, &dek_aad(space, dek_id, generation, ark_id), wrapped)?;
    Ok(DataKey::new(dek_id, *bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ark_seal_opens_only_under_the_same_root_and_binding() {
        let w = WrapKey::derive(&[7u8; 64]);
        let ark = Ark::generate();
        let id = ArkId([1; 16]);
        let sealed = seal_ark(&w, &ark, &id, 1);
        assert!(open_ark(&w, &sealed, &id, 1, W_LABEL).unwrap().ct_eq(&ark));

        let other_root = WrapKey::derive(&[8u8; 64]);
        assert!(open_ark(&other_root, &sealed, &id, 1, W_LABEL).is_err());
        assert!(open_ark(&w, &sealed, &ArkId([2; 16]), 1, W_LABEL).is_err());
        assert!(open_ark(&w, &sealed, &id, 2, W_LABEL).is_err());
        assert!(open_ark(&w, &sealed, &id, 1, "tinycloud/at-rest/wrap/v2").is_err());
        let mut flipped = sealed.clone();
        flipped[20] ^= 1;
        assert!(open_ark(&w, &flipped, &id, 1, W_LABEL).is_err());
        assert!(open_ark(&w, &sealed[..sealed.len() - 1], &id, 1, W_LABEL).is_err());
    }

    #[test]
    fn chain_opens_older_generation_from_newer_only() {
        let (old, old_id) = (Ark::generate(), ArkId([1; 16]));
        let (new, new_id) = (Ark::generate(), ArkId([2; 16]));
        let chain = chain_ark(&new, &new_id, &old, &old_id, 1);
        assert!(open_chain(&new, &new_id, &chain, &old_id, 1)
            .unwrap()
            .ct_eq(&old));
        assert!(open_chain(&old, &new_id, &chain, &old_id, 1).is_err());
        assert!(open_chain(&new, &new_id, &chain, &old_id, 2).is_err());
        assert!(open_chain(&new, &old_id, &chain, &old_id, 1).is_err());
    }

    #[test]
    fn dek_wrap_binds_space_id_generation_and_ark() {
        let ark = Ark::generate();
        let id = ArkId([3; 16]);
        let kek = Kek::derive(&ark);
        let (wrapped, dek) = new_dek(&kek, "space-a", DekId::new(1), 1, &id);
        let back = unwrap_dek(&kek, &wrapped, "space-a", DekId::new(1), 1, &id).unwrap();
        assert_eq!(back.bytes(), dek.bytes());
        assert_eq!(back.id(), DekId::new(1));

        // A row moved to another space, id, generation or ARK fails.
        assert!(unwrap_dek(&kek, &wrapped, "space-b", DekId::new(1), 1, &id).is_err());
        assert!(unwrap_dek(&kek, &wrapped, "space-a", DekId::new(2), 1, &id).is_err());
        assert!(unwrap_dek(&kek, &wrapped, "space-a", DekId::new(1), 2, &id).is_err());
        assert!(unwrap_dek(&kek, &wrapped, "space-a", DekId::new(1), 1, &ArkId([4; 16])).is_err());
        assert!(unwrap_dek(
            &Kek::derive(&Ark::generate()),
            &wrapped,
            "space-a",
            DekId::new(1),
            1,
            &id
        )
        .is_err());
        // Length-prefixing: "ab"+"c" and "a"+"bc" style shifts can't collide.
        assert_ne!(
            dek_aad("ab", DekId::new(1), 1, &id),
            dek_aad("a", DekId::new(1), 1, &id)
        );
    }

    #[test]
    fn derived_keys_are_independent() {
        let ark = Ark::generate();
        let kek = Kek::derive(&ark);
        let nk = object_name_key(&ark);
        assert_ne!(&*kek.0, nk.bytes());
        assert_ne!(&*kek.0, ark.expose());
        assert_ne!(nk.bytes(), &*hkdf32(ark.expose(), CHAIN_INFO));
    }
}
