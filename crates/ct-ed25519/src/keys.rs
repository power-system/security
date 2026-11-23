use sha2::{Digest, Sha512};
#[cfg(feature = "zeroize")]
use zeroize::ZeroizeOnDrop;

use crate::point::{Affine, Ed25519Curve};
use crate::scalar::Ed25519Scalar;
use ct_curve_point::curve_model::ProjectiveCurvePoint;
use ct_curve_point::encoding::PointEncoding;
use ct_curve_point::scalar_mul::ScalarMul;
use ct_scalar::ScalarField;

#[cfg_attr(feature = "zeroize", derive(ZeroizeOnDrop))]
#[derive(Clone)]
pub struct SigningKey {
    seed: [u8; 32],
    scalar: Ed25519Scalar,
    prefix: [u8; 32],
    #[cfg_attr(feature = "zeroize", zeroize(skip))]
    verifying_key: VerifyingKey,
}

impl SigningKey {
    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        let h = Sha512::digest(seed);
        let mut s = [0u8; 32];
        s.copy_from_slice(&h[..32]);
        s[0] &= 248;
        s[31] &= 127;
        s[31] |= 64;
        let scalar = Ed25519Scalar::from_bytes_mod_order(&s);

        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..]);

        let a = Ed25519Curve::mul_base(&scalar).to_affine();
        Self {
            seed: *seed,
            scalar,
            prefix,
            verifying_key: VerifyingKey { point: a },
        }
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
    pub fn to_bytes(&self) -> [u8; 32] {
        self.seed
    }

    pub(crate) fn scalar(&self) -> &Ed25519Scalar {
        &self.scalar
    }
    pub(crate) fn prefix(&self) -> &[u8; 32] {
        &self.prefix
    }
}

#[derive(Clone, Copy)]
pub struct VerifyingKey {
    pub(crate) point: Affine,
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, signature::Error> {
        Affine::from_compressed(bytes)
            .map(|point| Self { point })
            .ok_or(signature::Error::new())
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.point.to_compressed(&mut out);
        out
    }
}
