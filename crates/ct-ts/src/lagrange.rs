//! Lagrange interpolation, split by secrecy.
//!
//! Coefficients are derived from public identifiers, so scalar inversion in
//! [`coefficients`] is allowed to be variable-time. Combining secret shares in
//! [`combine_shares`] uses only constant-time field multiplication and
//! addition.

use alloc::vec::Vec;

use crate::{Ciphersuite, PartyId};

/// Compute the Lagrange coefficient for each signer in `signers`.
///
/// For a signing set `S`, the coefficient for signer `i` is
///
/// ```text
/// lambda_i = product_{j in S, j != i} x_j / (x_j - x_i)
/// ```
///
/// `signers` must contain distinct, non-zero identifiers. The protocol entry
/// points always build this list from a `BTreeMap`, which guarantees both.
pub fn coefficients<C: Ciphersuite>(signers: &[PartyId]) -> Vec<C::Scalar> {
    let xs: Vec<C::Scalar> = signers
        .iter()
        .map(|identifier| C::scalar_from_u64(u64::from(identifier.get())))
        .collect();

    let mut result = Vec::with_capacity(xs.len());
    for (i, x_i) in xs.iter().enumerate() {
        let mut numerator = C::scalar_one();
        let mut denominator = C::scalar_one();

        for (j, x_j) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            numerator = C::scalar_mul(&numerator, x_j);
            denominator = C::scalar_mul(&denominator, &C::scalar_sub(x_j, x_i));
        }

        result.push(C::scalar_mul(&numerator, &C::scalar_invert(&denominator)));
    }

    result
}

/// Combine secret shares with public Lagrange coefficients.
///
/// This is the only place where shares are combined, and it uses just
/// constant-time `mul` and `add`.
pub fn combine_shares<C: Ciphersuite>(
    shares: &[C::Scalar],
    coefficients: &[C::Scalar],
) -> C::Scalar {
    assert!(
        !shares.is_empty(),
        "at least one share is required to combine"
    );
    assert_eq!(
        shares.len(),
        coefficients.len(),
        "each share must have a corresponding coefficient"
    );

    let mut combined = C::scalar_zero();
    for (share, coefficient) in shares.iter().zip(coefficients.iter()) {
        combined = C::scalar_add(&combined, &C::scalar_mul(share, coefficient));
    }
    combined
}
