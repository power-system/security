//! DKG round 2: share verification and key-package construction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{
    Round1Package, Round1Secret, commit_coefficients, evaluate_commitment,
    evaluate_point_commitment, identifier_scalar,
};
use crate::keys::{KeyPackage, PublicKeyPackage};
use crate::{Ciphersuite, Error, PartyId};

/// Complete DKG for one participant.
///
/// Every dealer's share is checked against its polynomial commitment. Valid
/// shares are summed into this participant's signing share, and the public
/// package is built from the summed coefficient commitments.
pub fn dkg_part2<C: Ciphersuite>(
    secret: Round1Secret<C>,
    own_id: PartyId,
    round1_packages: &BTreeMap<PartyId, Round1Package<C>>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error> {
    if round1_packages.is_empty() {
        return Err(Error::new());
    }

    // The dealer must have included its own package, otherwise the constant
    // term of the group polynomial is missing.
    let own_package = round1_packages.get(&own_id).ok_or_else(Error::new)?;
    let own_commitment = commit_coefficients::<C>(&secret.coefficients);
    if !commitments_equal::<C>(&own_commitment, &own_package.commitment) {
        return Err(Error::new());
    }

    let threshold = own_commitment.len();
    if threshold == 0 {
        return Err(Error::new());
    }

    let participants: Vec<PartyId> = own_package.shares.keys().copied().collect();
    if participants.is_empty() || participants.len() < threshold {
        return Err(Error::new());
    }
    if !participants.contains(&own_id) {
        return Err(Error::new());
    }
    if !round1_packages.keys().eq(participants.iter()) {
        return Err(Error::new());
    }

    let own_x = identifier_scalar::<C>(own_id);
    let mut signing_share = C::scalar_zero();

    for package in round1_packages.values() {
        if package.commitment.len() != threshold {
            return Err(Error::new());
        }
        if !package.shares.keys().eq(participants.iter()) {
            return Err(Error::new());
        }

        let share = *package.shares.get(&own_id).ok_or_else(Error::new)?;
        let expected = evaluate_commitment::<C>(&package.commitment, &own_x);
        if !bool::from(C::ct_eq(&C::mul_base(&share), &expected)) {
            return Err(Error::new());
        }

        signing_share = C::scalar_add(&signing_share, &share);
    }

    // Sum the coefficient commitments of every dealer. The result commits to
    // the sum of the dealers' polynomials.
    let mut combined = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        combined.push(C::identity());
    }
    for package in round1_packages.values() {
        for (accumulator, commitment) in combined.iter_mut().zip(package.commitment.iter()) {
            *accumulator = C::add(accumulator, &C::point_from_affine(commitment));
        }
    }

    let group_public_key = combined[0];
    if bool::from(C::ct_is_identity(&group_public_key)) {
        return Err(Error::new());
    }

    let mut verifying_shares = BTreeMap::new();
    for &participant in &participants {
        let x = identifier_scalar::<C>(participant);
        let verifying_share = evaluate_point_commitment::<C>(&combined, &x);
        verifying_shares.insert(participant, verifying_share);
    }

    let verifying_share = *verifying_shares.get(&own_id).ok_or_else(Error::new)?;

    Ok((
        KeyPackage {
            identifier: own_id,
            signing_share,
            verifying_share,
            group_public_key,
        },
        PublicKeyPackage {
            group_public_key,
            verifying_shares,
        },
    ))
}

fn commitments_equal<C: Ciphersuite>(lhs: &[C::Affine], rhs: &[C::Affine]) -> bool {
    lhs.len() == rhs.len()
        && lhs.iter().zip(rhs.iter()).all(|(left, right)| {
            bool::from(C::ct_eq(
                &C::point_from_affine(left),
                &C::point_from_affine(right),
            ))
        })
}
