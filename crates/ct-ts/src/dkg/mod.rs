//! Two-round distributed key generation using Pedersen VSS.

mod round1;
mod round2;

pub use round1::{Round1Package, Round1Secret, dkg_part1};
pub use round2::dkg_part2;

use alloc::vec::Vec;
use rand_core::{CryptoRng, Rng};

use crate::{Ciphersuite, PartyId};

/// Sample a uniformly distributed scalar by wide reduction.
fn random_scalar<C: Ciphersuite, R: Rng + CryptoRng>(rng: &mut R) -> C::Scalar {
    let mut bytes = alloc::vec![0u8; 2 * C::LIMBS * 8];
    rng.fill_bytes(&mut bytes);
    C::scalar_from_wide(&bytes)
}

/// Evaluate a scalar polynomial with Horner's rule.
fn evaluate_polynomial<C: Ciphersuite>(coefficients: &[C::Scalar], x: &C::Scalar) -> C::Scalar {
    let mut result = C::scalar_zero();
    for coefficient in coefficients.iter().rev() {
        result = C::scalar_add(&C::scalar_mul(&result, x), coefficient);
    }
    result
}

/// Commit to every coefficient of a polynomial.
pub(crate) fn commit_coefficients<C: Ciphersuite>(coefficients: &[C::Scalar]) -> Vec<C::Affine> {
    coefficients
        .iter()
        .map(|coefficient| C::to_affine(&C::mul_base(coefficient)))
        .collect()
}

/// Evaluate a polynomial commitment at `x`, producing `[f(x)]G`.
///
/// All inputs are public, but the group operations themselves are constant
/// time.
pub(crate) fn evaluate_commitment<C: Ciphersuite>(
    commitment: &[C::Affine],
    x: &C::Scalar,
) -> C::Point {
    let mut result = C::identity();
    for coefficient in commitment.iter().rev() {
        result = C::mul(&result, x);
        result = C::add(&result, &C::point_from_affine(coefficient));
    }
    result
}

/// Evaluate a polynomial commitment already in projective form.
pub(crate) fn evaluate_point_commitment<C: Ciphersuite>(
    commitment: &[C::Point],
    x: &C::Scalar,
) -> C::Point {
    let mut result = C::identity();
    for coefficient in commitment.iter().rev() {
        result = C::mul(&result, x);
        result = C::add(&result, coefficient);
    }
    result
}

/// Convert a participant identifier into its scalar representation.
pub(crate) fn identifier_scalar<C: Ciphersuite>(identifier: PartyId) -> C::Scalar {
    C::scalar_from_u64(u64::from(identifier.get()))
}
