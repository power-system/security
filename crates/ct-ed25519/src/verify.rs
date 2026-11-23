use sha2::{Digest, Sha512};
use signature::Verifier;

use crate::keys::VerifyingKey;
use crate::point::{Affine, Ed25519Curve};
use crate::scalar::Ed25519Scalar;
use crate::signature::Signature;
use ct_curve_point::curve_model::CurvePoint;
use ct_curve_point::encoding::PointEncoding;
use ct_curve_point::scalar_mul::ScalarMul;
use ct_scalar::ScalarField;
use subtle::ConstantTimeEq;

impl Verifier<Signature> for VerifyingKey {
    fn verify(&self, message: &[u8], sig: &Signature) -> Result<(), signature::Error> {
        // 1. strict R decode
        let r_point = Affine::from_compressed(sig.r_bytes()).ok_or(signature::Error::new())?;

        // 2. S must be canonical (< L)
        let s = Ed25519Scalar::from_canonical_bytes(sig.s_bytes()).ok_or(signature::Error::new())?;

        // 3. k = SHA-512(R || A || M) mod L
        let mut h = Sha512::new();
        h.update(sig.r_bytes());
        h.update(self.to_bytes());
        h.update(message);
        let k = Ed25519Scalar::from_bytes_wide(&h.finalize());

        // 4. check [S]B == R + [k]A
        let lhs = Ed25519Curve::mul_base(&s);
        let a = point_from_affine(&self.point);
        let r = point_from_affine(&r_point);
        let rhs = Ed25519Curve::mul(&a, &k).add(&r);
        // 公开数据路径，可用非恒定时间比较
        if bool::from(lhs.ct_eq(&rhs)) {
            Ok(())
        } else {
            Err(signature::Error::new())
        }
    }
}

fn point_from_affine(a: &Affine) -> crate::point::Point {
    // 把仿射 A 嵌入扩展坐标 (x:y:1:x*y)
    crate::point::Point::from_affine(a)
}
