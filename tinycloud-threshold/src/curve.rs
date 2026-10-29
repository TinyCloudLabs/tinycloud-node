//! BLS12-381 boundary. Sources: RFC 9380 §§5,8.8,J; pairing-friendly-curves
//! draft 11 §§2.5,4.2.1; blst 0.3.16 API documentation and README only.
//!
//! FFI inventory and invariants (also covering the inline fixture tests):
//! - blst_scalar_from_bendian / blst_bendian_from_scalar: exactly 32 bytes.
//! - blst_scalar_fr_check: canonical scalar, including zero; not sk_check.
//! - blst_scalar_from_be_bytes: BE modular reduction, slice length passed exactly.
//! - blst_scalar_from_uint64: four initialized native u64 limbs.
//! - blst_fr_from_scalar / blst_scalar_from_fr: canonical scalar ↔ Montgomery Fr.
//! - blst_fr_add / blst_fr_sub / blst_fr_mul: initialized Fr operands/results.
//! - blst_fr_inverse: constant-time inversion path, NEVER fr_eucl_inverse;
//!   zero is refused before inversion. All Fr temporaries have wiping guards.
//! - blst_p1_generator / blst_p2_generator: read-only static, public generator.
//! - blst_p1_uncompress / blst_p2_uncompress: exactly 48/96 input bytes; output
//!   is initialized and used only after SUCCESS.
//! - blst_p1_affine_on_curve / blst_p2_affine_on_curve and
//!   blst_p1_affine_in_g1 / blst_p2_affine_in_g2: explicit curve AND subgroup
//!   validation, separate from decompression (also exercised on RFC Q0 points).
//! - blst_p1_from_affine / blst_p2_from_affine: validated affine inputs only.
//! - blst_p1_compress / blst_p2_compress: exactly 48/96 writable output bytes.
//! - blst_p1_is_inf / blst_p2_is_inf: initialized group points; role controls
//!   whether a decoded infinity is accepted.
//! - blst_p1_is_equal / blst_p2_is_equal: initialized subgroup points.
//! - blst_p1_add_or_double / blst_p2_add_or_double: handles equal/zero operands.
//! - blst_p1_cneg / blst_p2_cneg: initialized, exclusively owned point.
//! - blst_p1_mult / blst_p2_mult: canonical scalar's 32-byte LE representation,
//!   fixed 255 bits, checked subgroup point, never unchecked or Pippenger APIs.
//! - blst_hash_to_g1 / blst_hash_to_g2: valid message/DST pointer-length pairs,
//!   empty augmentation; RFC 9380 random-oracle suites with cofactor clearing.
//! - blst_p1_to_affine / blst_p2_to_affine: initialized subgroup inputs;
//!   secret-affine outputs are guarded and wiped.
//! - blst_miller_loop / blst_miller_loop_n: initialized checked affine points;
//!   n pointer entries backed by stable arrays, no aliased mutable arguments.
//! - blst_fp12_one: read-only static public multiplicative identity.
//! - blst_fp12_mul: initialized Fp12 inputs, distinct initialized output.
//! - blst_final_exp: every exposed pairing is reduced, never a Miller output.
//! - blst_fp12_is_one: reduced initialized product.
//! - blst_bendian_from_fp: exactly 48 writable bytes per tower coefficient.
//!
//! All outputs are initialized before C writes and distinct from inputs.
//! Raw Copy field/point/Fp12 types never escape; owned wrappers wipe every limb
//! on drop. Explicit Clone of points creates another independently wiped owner.
//! Wiping is an in-memory lifecycle measure, not a durable-erasure guarantee.

use blst::*;
use rand_core::CryptoRngCore;
use std::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::Error;

pub(crate) struct Scalar(blst_scalar);

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar([REDACTED])")
    }
}

impl Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
impl Drop for Scalar {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Scalar {}

#[derive(Default)]
struct SecretFr(blst_fr);
impl Drop for SecretFr {
    fn drop(&mut self) {
        self.0.l.zeroize();
    }
}

macro_rules! scalar_binary {
    ($name:ident, $op:ident) => {
        pub(crate) fn $name(&self, rhs: &Self) -> Self {
            let mut a = SecretFr::default();
            let mut b = SecretFr::default();
            let mut c = SecretFr::default();
            let mut out = Self(blst_scalar::default());
            // SAFETY: canonical scalars; distinct, initialized Fr/output buffers.
            unsafe {
                blst_fr_from_scalar(&mut a.0, &self.0);
                blst_fr_from_scalar(&mut b.0, &rhs.0);
                $op(&mut c.0, &a.0, &b.0);
                blst_scalar_from_fr(&mut out.0, &c.0);
            }
            out
        }
    };
}

impl Scalar {
    #[cfg(test)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes: &[u8; 32] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
        let mut out = Self(blst_scalar::default());
        // SAFETY: exactly 32 readable bytes and initialized, distinct output.
        unsafe {
            blst_scalar_from_bendian(&mut out.0, bytes.as_ptr());
            if !blst_scalar_fr_check(&out.0) {
                return Err(Error::InvalidScalar);
            }
        }
        Ok(out)
    }

    /// The returned secret bytes must be guarded by their caller.
    #[cfg(test)]
    pub(crate) fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0; 32];
        // SAFETY: exactly 32 writable bytes; canonical initialized scalar.
        unsafe {
            blst_bendian_from_scalar(out.as_mut_ptr(), &self.0);
        }
        out
    }

    /// Big-endian reduction; sampling uses 64 bytes and H3 uses 48 bytes.
    pub(crate) fn reduce(bytes: &[u8]) -> Self {
        let mut out = Self(blst_scalar::default());
        if bytes.is_empty() {
            return out;
        }
        // SAFETY: readable slice of the stated length, initialized output.
        // The boolean reports nonzero; zero is a valid field element here.
        unsafe {
            blst_scalar_from_be_bytes(&mut out.0, bytes.as_ptr(), bytes.len());
        }
        out
    }

    pub(crate) fn from_u64(value: u64) -> Self {
        let limbs = Zeroizing::new([value, 0, 0, 0]);
        let mut out = Self(blst_scalar::default());
        // SAFETY: four readable u64 limbs; every u64 is less than r.
        unsafe {
            blst_scalar_from_uint64(&mut out.0, limbs.as_ptr());
        }
        out
    }

    pub(crate) fn random(rng: &mut impl CryptoRngCore, nonzero: bool) -> Self {
        let mut bytes = Zeroizing::new([0; 64]);
        loop {
            rng.fill_bytes(bytes.as_mut());
            let scalar = Self::reduce(bytes.as_ref());
            if !nonzero || !scalar.is_zero() {
                return scalar;
            }
        }
    }

    pub(crate) fn is_zero(&self) -> bool {
        bool::from(self.0.b.ct_eq(&[0; 32]))
    }

    #[cfg(test)]
    scalar_binary!(add, blst_fr_add);
    scalar_binary!(sub, blst_fr_sub);
    scalar_binary!(mul, blst_fr_mul);

    pub(crate) fn inverse(&self) -> Result<Self, Error> {
        if self.is_zero() {
            return Err(Error::InvalidScalar);
        }
        let mut a = SecretFr::default();
        let mut inverse = SecretFr::default();
        let mut out = Self(blst_scalar::default());
        // SAFETY: nonzero canonical scalar; constant-time (not Euclidean)
        // inverse entry point, initialized and distinct buffers.
        unsafe {
            blst_fr_from_scalar(&mut a.0, &self.0);
            blst_fr_inverse(&mut inverse.0, &a.0);
            blst_scalar_from_fr(&mut out.0, &inverse.0);
        }
        Ok(out)
    }
}

fn wipe_fp2(value: &mut blst_fp2) {
    for coefficient in &mut value.fp {
        coefficient.l.zeroize();
    }
}
fn wipe_p1(value: &mut blst_p1) {
    value.x.l.zeroize();
    value.y.l.zeroize();
    value.z.l.zeroize();
}
fn wipe_p2(value: &mut blst_p2) {
    wipe_fp2(&mut value.x);
    wipe_fp2(&mut value.y);
    wipe_fp2(&mut value.z);
}

#[derive(Default)]
struct Affine1(blst_p1_affine);
impl Drop for Affine1 {
    fn drop(&mut self) {
        self.0.x.l.zeroize();
        self.0.y.l.zeroize();
    }
}
#[derive(Default)]
struct Affine2(blst_p2_affine);
impl Drop for Affine2 {
    fn drop(&mut self) {
        wipe_fp2(&mut self.0.x);
        wipe_fp2(&mut self.0.y);
    }
}

macro_rules! point {
    ($name:ident, $raw:ident, $affine:ident, $size:literal,
     $generator:ident, $uncompress:ident, $on_curve:ident, $in_group:ident,
     $from_affine:ident, $compress:ident, $inf:ident, $equal:ident,
     $add:ident, $negate:ident, $mult:ident, $wipe:ident) => {
        #[derive(Clone)]
        pub(crate) struct $name($raw);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }
        impl Zeroize for $name {
            fn zeroize(&mut self) {
                $wipe(&mut self.0);
            }
        }
        impl Drop for $name {
            fn drop(&mut self) {
                self.zeroize();
            }
        }
        impl ZeroizeOnDrop for $name {}
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                // SAFETY: both points are initialized subgroup elements.
                unsafe { $equal(&self.0, &other.0) }
            }
        }
        impl Eq for $name {}
        impl $name {
            pub(crate) fn identity() -> Self {
                Self($raw::default())
            }
            pub(crate) fn generator() -> Self {
                // SAFETY: library's static, read-only public generator.
                Self(unsafe { *$generator() })
            }
            pub(crate) fn decode(bytes: &[u8], allow_identity: bool) -> Result<Self, Error> {
                let bytes: &[u8; $size] = bytes.try_into().map_err(|_| Error::InvalidLength)?;
                let mut affine = $affine::default();
                let mut out = Self::identity();
                // SAFETY: exact input size, initialized disjoint outputs.
                // Decompression is NOT relied upon for subgroup membership.
                unsafe {
                    if $uncompress(&mut affine.0, bytes.as_ptr()) != BLST_ERROR::BLST_SUCCESS {
                        return Err(Error::InvalidPoint);
                    }
                    if !$on_curve(&affine.0) {
                        return Err(Error::InvalidPoint);
                    }
                    if !$in_group(&affine.0) {
                        return Err(Error::InvalidPoint);
                    }
                    $from_affine(&mut out.0, &affine.0);
                }
                if out.encode().as_slice() != bytes.as_slice() {
                    return Err(Error::InvalidPoint);
                }
                if !allow_identity && out.is_identity() {
                    return Err(Error::IdentityPoint);
                }
                Ok(out)
            }
            /// Callers must guard encodings when the point is secret.
            pub(crate) fn encode(&self) -> [u8; $size] {
                let mut out = [0; $size];
                // SAFETY: exact writable output size and initialized point.
                unsafe {
                    $compress(out.as_mut_ptr(), &self.0);
                }
                out
            }
            pub(crate) fn is_identity(&self) -> bool {
                // SAFETY: initialized subgroup point.
                unsafe { $inf(&self.0) }
            }
            pub(crate) fn add(&self, rhs: &Self) -> Self {
                let mut out = Self::identity();
                // SAFETY: disjoint initialized subgroup operands/output.
                unsafe {
                    $add(&mut out.0, &self.0, &rhs.0);
                }
                out
            }
            // The complete group interface is exercised by S0.1 primitive tests.
            #[allow(dead_code)]
            pub(crate) fn sub(&self, rhs: &Self) -> Self {
                let mut negative = rhs.clone();
                // SAFETY: initialized, exclusively owned subgroup point.
                unsafe {
                    $negate(&mut negative.0, true);
                }
                self.add(&negative)
            }
            pub(crate) fn mul(&self, scalar: &Scalar) -> Self {
                let mut out = Self::identity();
                // SAFETY: canonical scalar below r has at most 255 bits;
                // 32 LE bytes readable, fixed-width checked point path.
                unsafe {
                    $mult(&mut out.0, &self.0, scalar.0.b.as_ptr(), 255);
                }
                out
            }
        }
    };
}

point!(
    G1,
    blst_p1,
    Affine1,
    48,
    blst_p1_generator,
    blst_p1_uncompress,
    blst_p1_affine_on_curve,
    blst_p1_affine_in_g1,
    blst_p1_from_affine,
    blst_p1_compress,
    blst_p1_is_inf,
    blst_p1_is_equal,
    blst_p1_add_or_double,
    blst_p1_cneg,
    blst_p1_mult,
    wipe_p1
);
point!(
    G2,
    blst_p2,
    Affine2,
    96,
    blst_p2_generator,
    blst_p2_uncompress,
    blst_p2_affine_on_curve,
    blst_p2_affine_in_g2,
    blst_p2_from_affine,
    blst_p2_compress,
    blst_p2_is_inf,
    blst_p2_is_equal,
    blst_p2_add_or_double,
    blst_p2_cneg,
    blst_p2_mult,
    wipe_p2
);

pub(crate) fn hash_g1(msg: &[u8], dst: &[u8]) -> G1 {
    let mut out = G1::identity();
    // SAFETY: readable pointer-length pairs, no augmentation, initialized output.
    unsafe {
        blst_hash_to_g1(
            &mut out.0,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        );
    }
    out
}
#[cfg(test)]
pub(crate) fn hash_g2(msg: &[u8], dst: &[u8]) -> G2 {
    let mut out = G2::identity();
    // SAFETY: readable pointer-length pairs, no augmentation, initialized output.
    unsafe {
        blst_hash_to_g2(
            &mut out.0,
            msg.as_ptr(),
            msg.len(),
            dst.as_ptr(),
            dst.len(),
            core::ptr::null(),
            0,
        );
    }
    out
}

// Also guards unreduced, internal Miller-loop temporaries. Only pairing()
// exposes this type outside this module, after final exponentiation.
pub(crate) struct Gt(blst_fp12);
impl fmt::Debug for Gt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Gt([REDACTED])")
    }
}
impl Zeroize for Gt {
    fn zeroize(&mut self) {
        for fp6 in &mut self.0.fp6 {
            for fp2 in &mut fp6.fp2 {
                wipe_fp2(fp2);
            }
        }
    }
}
impl Drop for Gt {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl ZeroizeOnDrop for Gt {}
impl Gt {
    /// Frozen tower order, NOT ZCash's reverse Fp2 coordinate order.
    /// The caller owns and must guard the returned secret bytes.
    pub(crate) fn encode(&self) -> [u8; 576] {
        let mut out = [0; 576];
        let coefficients = self
            .0
            .fp6
            .iter()
            .flat_map(|fp6| fp6.fp2.iter())
            .flat_map(|fp2| fp2.fp.iter());
        for (coefficient, bytes) in coefficients.zip(out.chunks_exact_mut(48)) {
            // SAFETY: each chunk is exactly 48 writable bytes, distinct input.
            unsafe {
                blst_bendian_from_fp(bytes.as_mut_ptr(), coefficient);
            }
        }
        out
    }
}

pub(crate) fn pairing(p: &G1, q: &G2) -> Gt {
    let mut pa = Affine1::default();
    let mut qa = Affine2::default();
    let mut miller = Gt(blst_fp12::default());
    let mut reduced = Gt(blst_fp12::default());
    // SAFETY: checked subgroup inputs, initialized distinct guarded buffers.
    unsafe {
        blst_p1_to_affine(&mut pa.0, &p.0);
        blst_p2_to_affine(&mut qa.0, &q.0);
        blst_miller_loop(&mut miller.0, &qa.0, &pa.0);
        blst_final_exp(&mut reduced.0, &miller.0);
    }
    reduced
}

/// Product pairing check, one final exponentiation. Protocol equations use
/// two or three terms. Larger inputs stream in bounded stack batches so they
/// require no allocation; each batch is one multi-Miller loop.
pub(crate) fn pairing_check(terms: &[(&G1, &G2)]) -> bool {
    // SAFETY: read-only static multiplicative identity, public data.
    let mut product = Gt(unsafe { *blst_fp12_one() });
    for batch in terms.chunks(16) {
        let mut ps: [Affine1; 16] = core::array::from_fn(|_| Affine1::default());
        let mut qs: [Affine2; 16] = core::array::from_fn(|_| Affine2::default());
        let mut pp = [core::ptr::null(); 16];
        let mut qp = [core::ptr::null(); 16];
        for (((pa, qa), (pptr, qptr)), (p, q)) in ps
            .iter_mut()
            .zip(qs.iter_mut())
            .zip(pp.iter_mut().zip(qp.iter_mut()))
            .zip(batch)
        {
            // SAFETY: checked points, distinct initialized stable affine owners.
            unsafe {
                blst_p1_to_affine(&mut pa.0, &p.0);
                blst_p2_to_affine(&mut qa.0, &q.0);
            }
            *pptr = &pa.0;
            *qptr = &qa.0;
        }
        let mut miller = Gt(blst_fp12::default());
        let mut next = Gt(blst_fp12::default());
        // SAFETY: batch.len() valid entries point into live stable arrays.
        // All input and output objects are initialized and disjoint.
        unsafe {
            blst_miller_loop_n(&mut miller.0, qp.as_ptr(), pp.as_ptr(), batch.len());
            blst_fp12_mul(&mut next.0, &product.0, &miller.0);
        }
        product = next;
    }
    let mut reduced = Gt(blst_fp12::default());
    // SAFETY: initialized product; distinct reduced destination.
    unsafe {
        blst_final_exp(&mut reduced.0, &product.0);
        blst_fp12_is_one(&reduced.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;
    use serde_json::Value;

    const R: &str = "73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001";
    const P: &str = "1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab";

    fn fixture(g2: bool) -> Value {
        serde_json::from_str(if g2 {
            include_str!("../vectors/v1/rfc9380-g2.json")
        } else {
            include_str!("../vectors/v1/rfc9380-g1.json")
        })
        .unwrap()
    }

    // RFC coordinates use c0 + I*c1; compressed G2 puts c1 before c0.
    fn compressed(case: &Value, prefix: &str, g2: bool) -> Vec<u8> {
        let x = case["outputs"][format!("{prefix}.x")].as_str().unwrap();
        let y = case["outputs"][format!("{prefix}.y")].as_str().unwrap();
        let xs: Vec<_> = x.split("+ I * ").collect();
        let ys: Vec<_> = y.split("+ I * ").collect();
        let p = hex::decode(P).unwrap();
        let mut neg = Vec::new();
        for part in &ys {
            let mut borrow = 0i16;
            let mut n = vec![0u8; 48];
            for ((dst, a), b) in n
                .iter_mut()
                .rev()
                .zip(p.iter().rev())
                .zip(hex::decode(part).unwrap().iter().rev())
            {
                let v = i16::from(*a) - i16::from(*b) - borrow;
                *dst = v.rem_euclid(256) as u8;
                borrow = i16::from(v < 0);
            }
            neg.push(n);
        }
        let sign = if g2 && ys[1].bytes().any(|c| c != b'0') {
            hex::decode(ys[1]).unwrap() > neg[1]
        } else {
            hex::decode(ys[0]).unwrap() > neg[0]
        };
        let mut out = if g2 {
            hex::decode(format!("{}{}", xs[1], xs[0])).unwrap()
        } else {
            hex::decode(xs[0]).unwrap()
        };
        out[0] |= 0x80 | if sign { 0x20 } else { 0 };
        out
    }

    #[test]
    fn rfc9380_appendix_j_g1_sswu_ro() {
        let f = fixture(false);
        for case in f["cases"].as_array().unwrap() {
            let p = hash_g1(
                case["inputs"]["msg"].as_str().unwrap().as_bytes(),
                f["dst"].as_str().unwrap().as_bytes(),
            );
            assert_eq!(p.encode().as_slice(), compressed(case, "P", false));
            assert_eq!(G1::decode(&p.encode(), false).unwrap(), p);
        }
    }

    #[test]
    fn rfc9380_appendix_j_g2_sswu_ro() {
        let f = fixture(true);
        for case in f["cases"].as_array().unwrap() {
            let p = hash_g2(
                case["inputs"]["msg"].as_str().unwrap().as_bytes(),
                f["dst"].as_str().unwrap().as_bytes(),
            );
            assert_eq!(p.encode().as_slice(), compressed(case, "P", true));
            assert_eq!(G2::decode(&p.encode(), false).unwrap(), p);
        }
    }

    #[test]
    fn rfc9380_pre_cofactor_points_rejected_explicitly() {
        for g2 in [false, true] {
            let f = fixture(g2);
            let bytes = compressed(&f["cases"][0], "Q0", g2);
            if g2 {
                let mut affine = blst_p2_affine::default();
                // SAFETY: fixture is exactly 96 bytes; destination initialized and distinct.
                unsafe {
                    assert_eq!(
                        blst_p2_uncompress(&mut affine, bytes.as_ptr()),
                        BLST_ERROR::BLST_SUCCESS
                    );
                    assert!(blst_p2_affine_on_curve(&affine));
                    assert!(!blst_p2_affine_in_g2(&affine));
                }
                assert_eq!(G2::decode(&bytes, true), Err(Error::InvalidPoint));
            } else {
                let mut affine = blst_p1_affine::default();
                // SAFETY: fixture is exactly 48 bytes; destination initialized and distinct.
                unsafe {
                    assert_eq!(
                        blst_p1_uncompress(&mut affine, bytes.as_ptr()),
                        BLST_ERROR::BLST_SUCCESS
                    );
                    assert!(blst_p1_affine_on_curve(&affine));
                    assert!(!blst_p1_affine_in_g1(&affine));
                }
                assert_eq!(G1::decode(&bytes, true), Err(Error::InvalidPoint));
            }
        }
    }

    #[test]
    fn scalar_canonical_boundaries_and_modular_arithmetic() {
        assert!(Scalar::from_bytes(&[]).is_err());
        assert!(Scalar::from_bytes(&[0; 31]).is_err());
        assert!(Scalar::from_bytes(&[0; 33]).is_err());
        assert!(Scalar::from_bytes(&hex::decode(R).unwrap()).is_err());
        assert!(Scalar::from_bytes(&[255; 32]).is_err());
        let zero = Scalar::from_bytes(&[0; 32]).unwrap();
        assert!(zero.is_zero());
        assert_eq!(zero.inverse().unwrap_err(), Error::InvalidScalar);
        let one = Scalar::from_u64(1);
        let minus_one = zero.sub(&one);
        assert!(minus_one.add(&one).is_zero());
        assert_eq!(minus_one.mul(&minus_one).to_bytes(), one.to_bytes());
        assert_eq!(
            Scalar::reduce(&hex::decode(R).unwrap()).to_bytes(),
            zero.to_bytes()
        );
        assert_eq!(
            hex::encode(Scalar::reduce(&[255; 48]).to_bytes()),
            "2dbeaf1fd4843acb7abbe5687369510a9277efb8ac0a600dcf2ab21bf81f712c"
        );
        assert_eq!(
            hex::encode(Scalar::reduce(&[255; 64]).to_bytes()),
            "0748d9d99f59ff1105d314967254398f2b6cedcb87925c23c999e990f3f29c6c"
        );
        assert_eq!(
            Scalar::from_bytes(&minus_one.to_bytes())
                .unwrap()
                .to_bytes(),
            minus_one.to_bytes()
        );
        let three = Scalar::from_u64(3);
        assert_eq!(
            three.mul(&three.inverse().unwrap()).to_bytes(),
            one.to_bytes()
        );
        assert_eq!(format!("{three:?}"), "Scalar([REDACTED])");
    }

    #[test]
    fn point_decoder_lengths_flags_coordinates_and_roles() {
        assert!(G1::decode(&[0; 47], true).is_err());
        assert!(G1::decode(&[0; 49], true).is_err());
        assert!(G2::decode(&[0; 95], true).is_err());
        assert!(G2::decode(&[0; 97], true).is_err());
        for size in [48, 96] {
            let decode = |b: &[u8], allow| {
                if size == 48 {
                    G1::decode(b, allow).map(|_| ())
                } else {
                    G2::decode(b, allow).map(|_| ())
                }
            };
            let mut inf = vec![0; size];
            inf[0] = 0xc0;
            assert!(decode(&inf, true).is_ok());
            assert_eq!(decode(&inf, false), Err(Error::IdentityPoint));
            inf[0] = 0xe0;
            assert!(decode(&inf, true).is_err());
            inf[0] = 0xc0;
            inf[size - 1] = 1;
            assert!(decode(&inf, true).is_err());
            assert!(decode(&vec![0; size], true).is_err());
            let mut x = vec![0; size];
            x[..48].copy_from_slice(&hex::decode(P).unwrap());
            x[0] |= 0x80;
            assert!(decode(&x, true).is_err());
            let mut valid = if size == 48 {
                G1::generator().encode().to_vec()
            } else {
                G2::generator().encode().to_vec()
            };
            valid[0] &= 0x7f;
            assert!(decode(&valid, true).is_err());
        }
        // RFC 9380 §8.8 equations: 5 is nonsquare in Fp; the Fp2
        // norm of 4+4I is 32, also nonsquare (Appendix I.5).
        let mut off1 = [0; 48];
        off1[0] = 0x80;
        off1[47] = 1;
        assert_eq!(G1::decode(&off1, true), Err(Error::InvalidPoint));
        let mut off2 = [0; 96];
        off2[0] = 0x80;
        assert_eq!(G2::decode(&off2, true), Err(Error::InvalidPoint));
    }

    #[test]
    fn group_laws_pairing_and_single_final_exponentiation_product() {
        let a = Scalar::from_u64(7);
        let b = Scalar::from_u64(11);
        let p = G1::generator();
        let q = G2::generator();
        assert_eq!(p.add(&p), p.mul(&Scalar::from_u64(2)));
        assert_eq!(q.add(&q), q.mul(&Scalar::from_u64(2)));
        assert!(p.sub(&p).is_identity());
        assert!(q.sub(&q).is_identity());
        assert!(p.mul(&Scalar::from_u64(0)).is_identity());
        assert!(q.mul(&Scalar::from_u64(0)).is_identity());
        assert_eq!(
            pairing(&p.mul(&a), &q.mul(&b)).encode(),
            pairing(&p.mul(&a.mul(&b)), &q).encode()
        );
        let pa = p.mul(&a);
        let qa = q.mul(&a);
        let neg = G1::identity().sub(&p);
        assert!(pairing_check(&[(&pa, &q), (&neg, &qa)]));
        assert!(!pairing_check(&[(&pa, &q), (&neg, &q)]));
        assert!(pairing_check(&[]));
        let identity = pairing(&G1::identity(), &q).encode();
        assert_eq!(identity[47], 1);
        assert!(identity[..47].iter().all(|b| *b == 0));
        assert!(identity[48..].iter().all(|b| *b == 0));
        assert_ne!(pairing(&p, &q).encode(), identity);
        let mut secret = Scalar::from_u64(99);
        secret.zeroize();
        assert!(secret.is_zero());
        let mut point = p;
        point.zeroize();
        assert!(point.is_identity());
        let mut point = q;
        point.zeroize();
        assert!(point.is_identity());
        let mut gt = pairing(&G1::generator(), &G2::generator());
        gt.zeroize();
        assert_eq!(gt.encode(), [0; 576]);
    }

    #[test]
    fn scalar_sampling_uses_64_bytes_and_retries_only_required_zero() {
        struct Draws {
            calls: usize,
        }
        impl rand_core::RngCore for Draws {
            fn next_u32(&mut self) -> u32 {
                panic!("sampling must fill 64 bytes")
            }
            fn next_u64(&mut self) -> u64 {
                panic!("sampling must fill 64 bytes")
            }
            fn fill_bytes(&mut self, dest: &mut [u8]) {
                assert_eq!(dest.len(), 64);
                dest.fill(if self.calls == 0 { 0 } else { 1 });
                self.calls += 1;
            }
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
                self.fill_bytes(dest);
                Ok(())
            }
        }
        impl rand_core::CryptoRng for Draws {}
        let mut rng = Draws { calls: 0 };
        assert!(Scalar::random(&mut rng, false).is_zero());
        assert_eq!(rng.calls, 1);
        let mut rng = Draws { calls: 0 };
        let s = Scalar::random(&mut rng, true);
        assert_eq!(rng.calls, 2);
        assert_eq!(s.to_bytes(), Scalar::reduce(&[1; 64]).to_bytes());
    }

    proptest! {
        #[test]
        fn scalar_random_bytes_reject_or_canonical(bytes in prop::collection::vec(any::<u8>(), 0..80)) {
            if let Ok(s) = Scalar::from_bytes(&bytes) {
                let encoded = s.to_bytes();
                prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
            }
        }
        #[test]
        fn points_random_bytes_reject_or_canonical(bytes in prop::collection::vec(any::<u8>(), 0..110)) {
            if let Ok(p) = G1::decode(&bytes, true) {
                let encoded = p.encode();
                prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
            }
            if let Ok(p) = G2::decode(&bytes, true) {
                let encoded = p.encode();
                prop_assert_eq!(encoded.as_slice(), bytes.as_slice());
            }
        }
        #[test]
        fn random_scalar_and_point_roundtrips(seed in any::<[u8;32]>(), offset in 0usize..96, mask in any::<u8>()) {
            let mut rng = ChaCha20Rng::from_seed(seed);
            let s = Scalar::random(&mut rng, true);
            prop_assert!(!s.is_zero());
            prop_assert_eq!(Scalar::from_bytes(&s.to_bytes()).unwrap().to_bytes(), s.to_bytes());
            prop_assert_eq!(s.mul(&s.inverse().unwrap()).to_bytes(), Scalar::from_u64(1).to_bytes());
            let p = G1::generator().mul(&s); let q = G2::generator().mul(&s);
            prop_assert_eq!(G1::decode(&p.encode(), false).unwrap(), p.clone());
            prop_assert_eq!(G2::decode(&q.encode(), false).unwrap(), q.clone());
            let mut sb = s.to_bytes(); sb[offset % 32] ^= mask;
            if let Ok(s) = Scalar::from_bytes(&sb) { prop_assert_eq!(s.to_bytes(), sb); }
            let mut pb = p.encode(); pb[offset % 48] ^= mask;
            if let Ok(p) = G1::decode(&pb, true) { prop_assert_eq!(p.encode(), pb); }
            let mut qb = q.encode(); qb[offset] ^= mask;
            if let Ok(q) = G2::decode(&qb, true) { prop_assert_eq!(q.encode(), qb); }
        }
    }
}
