use sha2::{Digest, Sha512};
use signature::Signer;

use crate::keys::SigningKey;
use crate::point::Ed25519Curve;
use crate::scalar::Ed25519Scalar;
use crate::signature::Signature;
use ct_curve_point::curve_model::ProjectiveCurvePoint;
use ct_curve_point::encoding::PointEncoding;
use ct_curve_point::scalar_mul::ScalarMul;
use ct_fp::PrimeField;
use ct_scalar::ScalarField;

impl Signer<Signature> for SigningKey {
    fn try_sign(&self, message: &[u8]) -> Result<Signature, signature::Error> {
        // 1. r = SHA-512(prefix || message) mod L
        let mut h = Sha512::new();
        h.update(self.prefix());
        h.update(message);
        let r = Ed25519Scalar::from_bytes_wide(&h.finalize());

        // 2. R = [r]B
        let mut r_bytes = [0u8; 32];
        Ed25519Curve::mul_base(&r)
            .to_affine()
            .to_compressed(&mut r_bytes);

        // 3. k = SHA-512(R || A || message) mod L
        let mut h = Sha512::new();
        h.update(r_bytes);
        h.update(self.verifying_key().to_bytes());
        h.update(message);
        let k = Ed25519Scalar::from_bytes_wide(&h.finalize());

        // 4. S = r + k·s mod L
        let s = k.mul(self.scalar()).add(&r);

        // 5. assemble
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&r_bytes);
        bytes[32..].copy_from_slice(&s.to_bytes());
        Ok(Signature::from_bytes(&bytes))
    }
}
