//! Scalar-field interpolation at x=0.
use crate::{curve::Scalar, Error, MemberIndex};

pub(crate) fn lagrange(
    index: MemberIndex,
    indices: impl Iterator<Item = MemberIndex>,
) -> Result<Scalar, Error> {
    let x = Scalar::from_u64(u64::from(index.get()));
    let mut numerator = Scalar::from_u64(1);
    let mut denominator = Scalar::from_u64(1);
    for other in indices.filter(|j| *j != index) {
        let y = Scalar::from_u64(u64::from(other.get()));
        numerator = numerator.mul(&y);
        denominator = denominator.mul(&y.sub(&x));
    }
    Ok(numerator.mul(&denominator.inverse()?))
}

pub(crate) fn evaluate(coefficients: &[Scalar], x: &Scalar) -> Scalar {
    coefficients
        .iter()
        .rev()
        .fold(Scalar::from_u64(0), |value, c| value.mul(x).add(c))
}
