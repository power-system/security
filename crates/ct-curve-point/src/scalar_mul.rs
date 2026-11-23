use crate::curve_model::CurveModel;

/// Constant-time scalar multiplication.
pub trait ScalarMul<const LIMBS: usize>: CurveModel<LIMBS> {
    fn mul(point: &Self::ProjectivePoint, scalar: &Self::Scalar) -> Self::ProjectivePoint;

    fn mul_base(scalar: &Self::Scalar) -> Self::ProjectivePoint;
}
