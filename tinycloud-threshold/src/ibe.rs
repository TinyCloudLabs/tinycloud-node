//! Boneh–Franklin FullIdent for fixed-size data keys (SPEC §3.5).
use crate::{
    curve::{hash_g1, pairing, Scalar, G2},
    derive::{DerivedKey, MasterPublicKey},
    dst,
    encoding::Decoder,
    Error, IbeIdentity,
};
use core::fmt;
use rand_core::CryptoRngCore;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// A 256-bit data key. Its bytes are wiped when dropped.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey(Zeroizing<[u8; 32]>);
impl DataKey {
    /// Takes ownership of a fixed-width data key.
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
    /// Borrows the key bytes; callers own the lifecycle of any copy they make.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
impl fmt::Debug for DataKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DataKey([REDACTED])")
    }
}

/// Fixed-width `(U,V,W)` tuple; `U` is a non-identity G2 subgroup point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IbeCiphertext {
    pub(crate) u: G2,
    pub(crate) v: [u8; 32],
    pub(crate) w: [u8; 32],
}
impl IbeCiphertext {
    /// Canonical 160-byte FullIdent tuple.
    pub fn encode(&self) -> [u8; 160] {
        let mut out = [0; 160];
        for (dst, src) in out
            .iter_mut()
            .zip(self.u.encode().into_iter().chain(self.v).chain(self.w))
        {
            *dst = src;
        }
        out
    }
    /// Checks exact size, canonical point encoding, subgroup and U's field role.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut d = Decoder::new(bytes)?;
        let u = G2::decode(&d.fixed::<96>()?, false)?;
        let v = d.fixed()?;
        let w = d.fixed()?;
        d.finish()?;
        Ok(Self { u, v, w })
    }
}
impl TryFrom<&[u8]> for IbeCiphertext {
    type Error = Error;
    fn try_from(v: &[u8]) -> Result<Self, Error> {
        Self::decode(v)
    }
}

fn fo_input(sigma: &[u8; 32], message: &[u8; 32]) -> Zeroizing<[u8; 64]> {
    let mut out = Zeroizing::new([0; 64]);
    for (d, s) in out.iter_mut().zip(sigma.iter().chain(message)) {
        *d = *s;
    }
    out
}
fn xor(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut out = [0; 32];
    for ((d, a), b) in out.iter_mut().zip(a).zip(b) {
        *d = a ^ b;
    }
    out
}

/// Wraps a data key to an exact record or session identity under an mpk.
pub fn wrap_key(
    mpk: &MasterPublicKey,
    id: &IbeIdentity,
    key: &DataKey,
    rng: &mut impl CryptoRngCore,
) -> Result<IbeCiphertext, Error> {
    let mut sigma = Zeroizing::new([0; 32]);
    rng.fill_bytes(sigma.as_mut());
    let rho = dst::h3(&fo_input(&sigma, key.as_bytes()));
    wrap_with_rho(mpk, id, key, sigma, rho)
}

pub(crate) fn wrap_with_rho(
    mpk: &MasterPublicKey,
    id: &IbeIdentity,
    key: &DataKey,
    sigma: Zeroizing<[u8; 32]>,
    rho: Scalar,
) -> Result<IbeCiphertext, Error> {
    if rho.is_zero() {
        return Err(Error::DegenerateRandomness);
    }
    let u = G2::generator().mul(&rho);
    let ephemeral = Zeroizing::new(hash_g1(id.as_bytes(), dst::H1).mul(&rho));
    let gt = Zeroizing::new(pairing(&ephemeral, &mpk.0));
    let encoded = Zeroizing::new(gt.encode());
    let mask = Zeroizing::new(dst::h2(&encoded));
    let v = xor(&sigma, &mask);
    let mask = Zeroizing::new(dst::h4(&sigma));
    let w = xor(key.as_bytes(), &mask);
    Ok(IbeCiphertext { u, v, w })
}

/// Unwraps only with a key carrying the exact expected identity.
pub fn unwrap_key(
    key: &DerivedKey,
    expected_id: &IbeIdentity,
    ct: &IbeCiphertext,
) -> Result<DataKey, Error> {
    if key.identity != *expected_id {
        return Err(Error::WrongIdentity);
    }
    let gt = Zeroizing::new(pairing(&key.key, &ct.u));
    let encoded = Zeroizing::new(gt.encode());
    let mask = Zeroizing::new(dst::h2(&encoded));
    let sigma = Zeroizing::new(xor(&ct.v, &mask));
    let mask = Zeroizing::new(dst::h4(&sigma));
    let message = Zeroizing::new(xor(&ct.w, &mask));
    let rho = dst::h3(&fo_input(&sigma, &message));
    let expected = G2::generator().mul(&rho).encode();
    if rho.is_zero() || !bool::from(expected.ct_eq(&ct.u.encode())) {
        return Err(Error::InvalidCiphertext);
    }
    Ok(DataKey::new(*message))
}
