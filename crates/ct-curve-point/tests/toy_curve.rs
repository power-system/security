use ct_curve_point::{
    CurveModel, CurvePoint, ScalarMul,
    curve_model::{AffineCurvePoint, ProjectiveCurvePoint},
    encoding::PointEncoding,
};
use ct_scalar::ScalarField;
use ct_uint::Uint;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[derive(Clone, Copy, Debug)]
struct ToyScalar(u64);
impl ConstantTimeEq for ToyScalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for ToyScalar {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        ToyScalar(u64::conditional_select(&a.0, &b.0, c))
    }
}
const TOY_N: u64 = 0xFFFF_FFFF_FFFF_FFC5;
impl ct_fp::PrimeField<1> for ToyScalar {
    const MODULUS: Uint<1> = Uint::from_u64(TOY_N);
    fn mul(&self, rhs: &Self) -> Self {
        ToyScalar(((self.0 as u128 * rhs.0 as u128) % TOY_N as u128) as u64)
    }
    fn from_uint(v: Uint<1>) -> Self {
        ToyScalar(v.to_u64().unwrap())
    }
    fn to_uint(&self) -> Uint<1> {
        Uint::from_u64(self.0)
    }
}
impl ScalarField<1> for ToyScalar {}

#[derive(Clone, Copy)]
struct ToyProj(u64);
impl ConstantTimeEq for ToyProj {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for ToyProj {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        ToyProj(u64::conditional_select(&a.0, &b.0, c))
    }
}
impl CurvePoint for ToyProj {
    fn add(&self, _rhs: &Self) -> Self {
        *self
    }
    fn double(&self) -> Self {
        *self
    }
    fn neg(&self) -> Self {
        *self
    }
    fn ct_is_identity(&self) -> Choice {
        self.0.ct_eq(&0)
    }
}

#[derive(Clone, Copy)]
struct ToyAffine(u64);
impl ConstantTimeEq for ToyAffine {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}
impl ConditionallySelectable for ToyAffine {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        ToyAffine(u64::conditional_select(&a.0, &b.0, c))
    }
}
impl CurvePoint for ToyAffine {
    fn add(&self, _rhs: &Self) -> Self {
        *self
    }
    fn double(&self) -> Self {
        *self
    }
    fn neg(&self) -> Self {
        *self
    }
    fn ct_is_identity(&self) -> Choice {
        self.0.ct_eq(&0)
    }
}

struct ToyCurve;
impl CurveModel<1> for ToyCurve {
    type Scalar = ToyScalar;
    type ProjectivePoint = ToyProj;
    type AffinePoint = ToyAffine;
    fn identity() -> ToyProj {
        ToyProj(0)
    }
}

impl ProjectiveCurvePoint<1> for ToyProj {
    type Curve = ToyCurve;
    fn to_affine(&self) -> ToyAffine {
        ToyAffine(self.0)
    }
}

impl AffineCurvePoint<1> for ToyAffine {
    type Curve = ToyCurve;
    fn affine_x_bytes(&self) -> &[u8] {
        &[]
    }
    fn affine_y_bytes(&self) -> &[u8] {
        &[]
    }
}

impl PointEncoding for ToyAffine {
    const COMPRESSED_LEN: usize = 8;
    const UNCOMPRESSED_LEN: usize = 16;
    fn from_compressed(_b: &[u8]) -> Option<Self> {
        Some(ToyAffine(0))
    }
    fn from_uncompressed(_b: &[u8]) -> Option<Self> {
        Some(ToyAffine(0))
    }
    fn to_compressed(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
    }
    fn to_uncompressed(&self, out: &mut [u8]) {
        out[..8].copy_from_slice(&self.0.to_le_bytes());
        out[8..16].fill(0);
    }
    fn ct_is_valid(&self) -> Choice {
        Choice::from(1)
    }
}

impl ScalarMul<1> for ToyCurve {
    fn mul(p: &ToyProj, _s: &ToyScalar) -> ToyProj {
        *p
    }
    fn mul_base(_s: &ToyScalar) -> ToyProj {
        ToyProj(0)
    }
}

#[test]
fn trait_is_instantiable() {
    let p = ToyCurve::identity();
    assert!(bool::from(p.ct_is_identity()));
    let a = p.to_affine();
    assert!(bool::from(a.ct_is_valid()));
}
