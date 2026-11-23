//! Signing round 1: nonce generation and commitment.

use alloc::vec::Vec;

use rand_core::{CryptoRng, Rng};
use zeroize::ZeroizeOnDrop;

use crate::Ciphersuite;
use crate::keys::KeyPackage;

/// Secret nonce pair. Never sent to the coordinator.
#[derive(ZeroizeOnDrop)]
pub struct SigningNonces<C: Ciphersuite> {
    pub(crate) hiding: C::Scalar,
    pub(crate) binding: C::Scalar,
}

/// Public nonce commitments sent to the coordinator.
#[derive(Clone, Copy)]
pub struct SignCommitment<C: Ciphersuite> {
    /// Commitment to the hiding nonce.
    pub hiding: C::Affine,

    /// Commitment to the binding nonce.
    pub binding: C::Affine,
}

/// Run the first signing round.
///
/// Fresh randomness is mixed with the secret share through `H3`, as required
/// by RFC 9591. Only the commitments are published; the nonce values stay in
/// [`SigningNonces`].
pub fn sign_part1<C: Ciphersuite, R: Rng + CryptoRng>(
    rng: &mut R,
    key_package: &KeyPackage<C>,
) -> (SigningNonces<C>, SignCommitment<C>) {
    let hiding = nonce_generate::<C, R>(rng, &key_package.signing_share);
    let binding = nonce_generate::<C, R>(rng, &key_package.signing_share);

    (
        SigningNonces { hiding, binding },
        SignCommitment {
            hiding: C::to_affine(&C::mul_base(&hiding)),
            binding: C::to_affine(&C::mul_base(&binding)),
        },
    )
}

fn nonce_generate<C: Ciphersuite, R: Rng + CryptoRng>(
    rng: &mut R,
    secret: &C::Scalar,
) -> C::Scalar {
    let mut random = [0u8; 32];
    rng.fill_bytes(&mut random);

    let mut input = Vec::with_capacity(32 + C::LIMBS * 8);
    input.extend_from_slice(&random);
    input.extend_from_slice(&C::serialize_scalar(secret));
    C::H3(&input)
}
