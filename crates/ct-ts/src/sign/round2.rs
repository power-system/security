//! Signing round 2: signature-share generation and aggregation.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{
    SignCommitment, SigningNonces, compute_binding_factors, compute_challenge,
    compute_group_commitment,
};
use crate::keys::{KeyPackage, PublicKeyPackage};
use crate::lagrange;
use crate::{Ciphersuite, Error, PartyId};

/// Produce this participant's signature share.
///
/// The nonce values are consumed and wiped when this function returns.
pub fn sign_part2<C: Ciphersuite>(
    nonces: SigningNonces<C>,
    key_package: &KeyPackage<C>,
    message: &[u8],
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
) -> Result<C::Scalar, Error> {
    if commitments.is_empty() {
        return Err(Error::new());
    }

    let binding_factors =
        compute_binding_factors::<C>(&key_package.group_public_key, message, commitments);
    let own_binding_factor = *binding_factors
        .get(&key_package.identifier)
        .ok_or_else(Error::new)?;

    let group_commitment = compute_group_commitment::<C>(commitments, &binding_factors)?;
    let challenge =
        compute_challenge::<C>(&group_commitment, &key_package.group_public_key, message);

    let participants: Vec<PartyId> = commitments.keys().copied().collect();
    let coefficients = lagrange::coefficients::<C>(&participants);
    let own_index = participants
        .iter()
        .position(|identifier| *identifier == key_package.identifier)
        .ok_or_else(Error::new)?;
    let own_coefficient = coefficients[own_index];

    // z_i = d_i + rho_i * e_i + c * lambda_i * s_i
    let hiding = nonces.hiding;
    let binding = nonces.binding;

    let mut share = C::scalar_add(&hiding, &C::scalar_mul(&own_binding_factor, &binding));
    share = C::scalar_add(
        &share,
        &C::scalar_mul(
            &C::scalar_mul(&challenge, &own_coefficient),
            &key_package.signing_share,
        ),
    );
    Ok(share)
}

/// Aggregate signature shares into the ciphersuite's signature.
pub fn aggregate<C: Ciphersuite>(
    message: &[u8],
    public_key_package: &PublicKeyPackage<C>,
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
    shares: &BTreeMap<PartyId, C::Scalar>,
) -> Result<C::Signature, Error> {
    if commitments.is_empty() || commitments.len() != shares.len() {
        return Err(Error::new());
    }
    if !commitments.keys().eq(shares.keys()) {
        return Err(Error::new());
    }

    let binding_factors =
        compute_binding_factors::<C>(&public_key_package.group_public_key, message, commitments);
    let group_commitment = compute_group_commitment::<C>(commitments, &binding_factors)?;

    let mut z = C::scalar_zero();
    for share in shares.values() {
        z = C::scalar_add(&z, share);
    }

    Ok(C::signature(&C::to_affine(&group_commitment), &z))
}
