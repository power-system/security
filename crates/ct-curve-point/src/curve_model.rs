//! Curve model and point traits.

use ct_scalar::ScalarField;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

/// Operations every curve point must support, regardless of representation.
pub trait CurvePoint: Copy + Clone + ConstantTimeEq + ConditionallySelectable + Sized {
    fn add(&self, rhs: &Self) -> Self;
    fn double(&self) -> Self;
    fn neg(&self) -> Self;
    fn ct_is_identity(&self) -> Choice;
}

/// Projective points (extended Edwards, Jacobian Weierstrass) convert to affine.
pub trait ProjectiveCurvePoint<const LIMBS: usize>: CurvePoint {
    type Curve: CurveModel<LIMBS>;

    fn to_affine(&self) -> <Self::Curve as CurveModel<LIMBS>>::AffinePoint;
}

/// Affine points expose coordinates for encoding and decoding.
pub trait AffineCurvePoint<const LIMBS: usize>: CurvePoint {
    type Curve: CurveModel<LIMBS>;

    fn affine_x_bytes(&self) -> &[u8];
    fn affine_y_bytes(&self) -> &[u8];
}

/// A curve model with its scalar field and point types.
///
/// `LIMBS` is the number of 64-bit limbs in the base-field modulus. It is a
/// trait parameter rather than an associated constant so that it can be
/// forwarded to `ScalarField<LIMBS>` on stable Rust.
pub trait CurveModel<const LIMBS: usize> {
    type Scalar: ScalarField<LIMBS>;
    type ProjectivePoint: ProjectiveCurvePoint<LIMBS, Curve = Self>;
    type AffinePoint: AffineCurvePoint<LIMBS, Curve = Self>;

    fn identity() -> Self::ProjectivePoint;
}
