use ct_curve_point::curve_model::{AffineCurvePoint, CurveModel, CurvePoint, ProjectiveCurvePoint};
use ct_curve_point::encoding::PointEncoding;
use ct_curve_point::scalar_mul::ScalarMul;
use ct_fp::PrimeField;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

use crate::field::{Ed25519Fp, basepoint_x, basepoint_y, d, sqrt_m1, two_d};
use crate::scalar::Ed25519Scalar;

// ===== Projective point (extended coordinates X:Y:Z:T) =====

#[derive(Clone, Copy, Debug)]
pub struct Ed25519Point {
    x: Ed25519Fp,
    y: Ed25519Fp,
    z: Ed25519Fp,
    t: Ed25519Fp,
}

impl ConstantTimeEq for Ed25519Point {
    fn ct_eq(&self, other: &Self) -> Choice {
        // (X1:Y1:Z1) == (X2:Y2:Z2) iff X1*Z2 == X2*Z1 && Y1*Z2 == Y2*Z1
        let xz = self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z));
        let yz = self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z));
        xz & yz
    }
}

impl ConditionallySelectable for Ed25519Point {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self {
            x: Ed25519Fp::conditional_select(&a.x, &b.x, c),
            y: Ed25519Fp::conditional_select(&a.y, &b.y, c),
            z: Ed25519Fp::conditional_select(&a.z, &b.z, c),
            t: Ed25519Fp::conditional_select(&a.t, &b.t, c),
        }
    }
}

impl Ed25519Point {
    /// The neutral element of the group, `(0 : 1 : 1 : 0)`.
    pub fn identity() -> Self {
        Self {
            x: Ed25519Fp::ZERO,
            y: Ed25519Fp::ONE,
            z: Ed25519Fp::ONE,
            t: Ed25519Fp::ZERO,
        }
    }

    /// The Ed25519 base point (generator).
    pub fn basepoint() -> Self {
        let x = basepoint_x();
        let y = basepoint_y();
        Self {
            x,
            y,
            z: Ed25519Fp::ONE,
            t: x.mul(&y),
        }
    }

    /// Embed an affine point as a projective point.
    pub fn from_affine(affine: &Ed25519Affine) -> Self {
        Self::from_affine_coords(affine.x, affine.y)
    }

    pub(crate) fn from_affine_coords(x: Ed25519Fp, y: Ed25519Fp) -> Self {
        Self {
            x,
            y,
            z: Ed25519Fp::ONE,
            t: x.mul(&y),
        }
    }
}

impl CurvePoint for Ed25519Point {
    fn add(&self, rhs: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&rhs.y.sub(&rhs.x));
        let b = self.y.add(&self.x).mul(&rhs.y.add(&rhs.x));
        let c = self.t.mul(&two_d()).mul(&rhs.t);
        let d = self.z.add(&self.z).mul(&rhs.z);
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().add(&self.z.square());
        let d = a.neg();
        let e = self.x.add(&self.y).square().sub(&a).sub(&b);
        let g = d.add(&b);
        let f = g.sub(&c);
        let h = d.sub(&b);
        Self {
            x: e.mul(&f),
            y: g.mul(&h),
            z: f.mul(&g),
            t: e.mul(&h),
        }
    }

    fn neg(&self) -> Self {
        Self {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    fn ct_is_identity(&self) -> Choice {
        self.x.ct_is_zero() & self.y.ct_eq(&self.z)
    }
}

// ===== Affine point =====

#[derive(Clone, Copy, Debug)]
pub struct Ed25519Affine {
    pub(crate) x: Ed25519Fp,
    pub(crate) y: Ed25519Fp,
    x_bytes: [u8; 32],
    y_bytes: [u8; 32],
}

impl Ed25519Affine {
    fn new(x: Ed25519Fp, y: Ed25519Fp) -> Self {
        Self {
            x,
            y,
            x_bytes: x.to_bytes(),
            y_bytes: y.to_bytes(),
        }
    }
}

impl ConstantTimeEq for Ed25519Affine {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.x.ct_eq(&other.x) & self.y.ct_eq(&other.y)
    }
}

impl ConditionallySelectable for Ed25519Affine {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self::new(
            Ed25519Fp::conditional_select(&a.x, &b.x, c),
            Ed25519Fp::conditional_select(&a.y, &b.y, c),
        )
    }
}

impl AffineCurvePoint<4> for Ed25519Affine {
    type Curve = Ed25519Curve;

    fn affine_x_bytes(&self) -> &[u8] {
        &self.x_bytes
    }

    fn affine_y_bytes(&self) -> &[u8] {
        &self.y_bytes
    }
}

impl CurvePoint for Ed25519Affine {
    fn add(&self, _rhs: &Self) -> Self {
        unimplemented!("use Ed25519Point")
    }
    fn double(&self) -> Self {
        unimplemented!("use Ed25519Point")
    }
    fn neg(&self) -> Self {
        Self::new(self.x.neg(), self.y)
    }
    fn ct_is_identity(&self) -> Choice {
        self.x.ct_is_zero() & self.y.ct_eq(&Ed25519Fp::ONE)
    }
}

// ===== Curve model =====

pub struct Ed25519Curve;

impl CurveModel<4> for Ed25519Curve {
    type Scalar = Ed25519Scalar;
    type ProjectivePoint = Ed25519Point;
    type AffinePoint = Ed25519Affine;
    fn identity() -> Ed25519Point {
        Ed25519Point::identity()
    }
}

impl ProjectiveCurvePoint<4> for Ed25519Point {
    type Curve = Ed25519Curve;
    fn to_affine(&self) -> Ed25519Affine {
        let z_inv = self.z.invert();
        Ed25519Affine::new(self.x.mul(&z_inv), self.y.mul(&z_inv))
    }
}

impl ScalarMul<4> for Ed25519Curve {
    /// Constant-time double-and-add.
    fn mul(point: &Ed25519Point, scalar: &Ed25519Scalar) -> Ed25519Point {
        let mut acc = Ed25519Point::identity();
        let bytes = scalar.to_bytes();
        for byte in bytes.iter().rev() {
            for bit in (0..8).rev() {
                acc = acc.double();
                let b = Choice::from((byte >> bit) & 1);
                let sum = acc.add(point);
                acc = Ed25519Point::conditional_select(&acc, &sum, b);
            }
        }
        acc
    }

    /// 0.0.1: mul_base falls back to generic mul. 0.0.2 adds precomputed table.
    fn mul_base(scalar: &Ed25519Scalar) -> Ed25519Point {
        Self::mul(&Ed25519Point::basepoint(), scalar)
    }
}

// ===== Encoding =====

impl PointEncoding for Ed25519Affine {
    const COMPRESSED_LEN: usize = 32;
    const UNCOMPRESSED_LEN: usize = 64;

    fn from_compressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 32 {
            return None;
        }
        let mut yb = [0u8; 32];
        yb.copy_from_slice(bytes);
        let sign = yb[31] >> 7;
        yb[31] &= 0x7F;
        let y = Ed25519Fp::from_bytes(&yb)?;

        let y2 = y.square();
        let u = y2.sub(&Ed25519Fp::ONE);
        let v = d().mul(&y2).add(&Ed25519Fp::ONE);

        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        // exponent = (p-5)/8 = 2^252 - 3
        let mut exp = [0xFFu8; 32];
        exp[0] = 0xFD;
        exp[31] = 0x0F;
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow(&exp));

        let vx2 = v.mul(&x.square());
        if !bool::from(vx2.ct_eq(&u)) {
            if bool::from(vx2.ct_eq(&u.neg())) {
                x = x.mul(&sqrt_m1());
            } else {
                return None;
            }
        }

        if bool::from(x.is_negative()) != (sign == 1) {
            x = x.neg();
        }
        if bool::from(x.ct_is_zero()) && sign == 1 {
            return None;
        }
        Some(Self::new(x, y))
    }

    fn from_uncompressed(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        let x = Ed25519Fp::from_bytes(bytes[..32].try_into().ok()?)?;
        let y = Ed25519Fp::from_bytes(bytes[32..].try_into().ok()?)?;
        let p = Self::new(x, y);
        if bool::from(p.ct_is_valid()) {
            Some(p)
        } else {
            None
        }
    }

    fn to_compressed(&self, out: &mut [u8]) {
        let mut yb = self.y.to_bytes();
        if bool::from(self.x.is_negative()) {
            yb[31] |= 0x80;
        }
        out[..32].copy_from_slice(&yb);
    }

    fn to_uncompressed(&self, out: &mut [u8]) {
        out[..32].copy_from_slice(&self.x.to_bytes());
        out[32..64].copy_from_slice(&self.y.to_bytes());
    }

    fn ct_is_valid(&self) -> Choice {
        // -x^2 + y^2 == 1 + d*x^2*y^2
        let x2 = self.x.square();
        let y2 = self.y.square();
        let lhs = y2.sub(&x2);
        let rhs = Ed25519Fp::ONE.add(&d().mul(&x2).mul(&y2));
        lhs.ct_eq(&rhs)
    }
}

// ===== Re-exports for keys/sign/verify =====

pub(crate) use Ed25519Affine as Affine;
pub(crate) use Ed25519Point as Point;
