//! Two-round FROST signing.

mod round1;
mod round2;

pub use round1::{SignCommitment, SigningNonces, sign_part1};
pub use round2::{aggregate, sign_part2};

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::dkg::identifier_scalar;
use crate::{Ciphersuite, Error, PartyId};

/// RFC 9591 binding factors for a commitment list.
pub(crate) fn compute_binding_factors<C: Ciphersuite>(
    group_public_key: &C::Point,
    message: &[u8],
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
) -> BTreeMap<PartyId, C::Scalar> {
    let mut encoded_commitments = Vec::new();
    for (identifier, commitment) in commitments {
        encoded_commitments
            .extend_from_slice(&C::serialize_scalar(&identifier_scalar::<C>(*identifier)));
        encoded_commitments.extend_from_slice(&C::serialize_affine(&commitment.hiding));
        encoded_commitments.extend_from_slice(&C::serialize_affine(&commitment.binding));
    }

    let message_hash = C::H4(message);
    let commitment_hash = C::H5(&encoded_commitments);

    let mut prefix = C::serialize_point(group_public_key);
    prefix.extend_from_slice(&message_hash);
    prefix.extend_from_slice(&commitment_hash);

    let mut factors = BTreeMap::new();
    for identifier in commitments.keys() {
        let mut input = prefix.clone();
        input.extend_from_slice(&C::serialize_scalar(&identifier_scalar::<C>(*identifier)));
        factors.insert(*identifier, C::H1(&input));
    }
    factors
}

/// RFC 9591 group commitment `R = sum(D_k + rho_k E_k)`.
pub(crate) fn compute_group_commitment<C: Ciphersuite>(
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
    binding_factors: &BTreeMap<PartyId, C::Scalar>,
) -> Result<C::Point, Error> {
    let mut group_commitment = C::identity();

    for (identifier, commitment) in commitments {
        let binding_factor = binding_factors.get(identifier).ok_or_else(Error::new)?;

        let hiding = C::point_from_affine(&commitment.hiding);
        let binding = C::point_from_affine(&commitment.binding);
        let bound_binding = C::mul(&binding, binding_factor);

        group_commitment = C::add(&group_commitment, &hiding);
        group_commitment = C::add(&group_commitment, &bound_binding);
    }

    Ok(group_commitment)
}

/// RFC 9591 signature challenge `c = H2(R || Y || message)`.
pub(crate) fn compute_challenge<C: Ciphersuite>(
    group_commitment: &C::Point,
    group_public_key: &C::Point,
    message: &[u8],
) -> C::Scalar {
    let mut input = C::serialize_point(group_commitment);
    input.extend_from_slice(&C::serialize_point(group_public_key));
    input.extend_from_slice(message);
    C::H2(&input)
}
