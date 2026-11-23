//! DKG round 1: polynomial generation, commitments, and shares.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use rand_core::{CryptoRng, Rng};
use zeroize::Zeroize;

use super::{commit_coefficients, evaluate_polynomial, identifier_scalar, random_scalar};
use crate::{Ciphersuite, Error, PartyId};

/// Secret state retained by a dealer between DKG rounds.
pub struct Round1Secret<C: Ciphersuite> {
    pub(crate) coefficients: Vec<C::Scalar>,
}

impl<C: Ciphersuite> Drop for Round1Secret<C> {
    fn drop(&mut self) {
        for coefficient in self.coefficients.iter_mut() {
            coefficient.zeroize();
        }
    }
}

/// Public commitments and per-recipient shares produced by a dealer.
///
/// In a networked deployment each recipient receives only its own entry from
/// `shares`; the transport and encryption layer are out of scope for v0.0.1.
pub struct Round1Package<C: Ciphersuite> {
    /// Coefficient commitments `[a_0]G, [a_1]G, ...`.
    pub commitment: Vec<C::Affine>,

    /// Evaluated share for each participant.
    pub shares: BTreeMap<PartyId, C::Scalar>,
}

impl<C: Ciphersuite> Drop for Round1Package<C> {
    fn drop(&mut self) {
        for share in self.shares.values_mut() {
            share.zeroize();
        }
    }
}

/// Run the first DKG round.
///
/// `threshold` is the minimum number of participants required to sign. A
/// degree `threshold - 1` polynomial is sampled, and every participant
/// receives `f(x_i)`.
///
/// The returned [`Round1Package`] is sent to the other participants. The
/// [`Round1Secret`] stays with the dealer and is consumed by
/// [`super::dkg_part2`].
pub fn dkg_part1<C: Ciphersuite, R: Rng + CryptoRng>(
    rng: &mut R,
    threshold: u16,
    participants: &[PartyId],
) -> Result<(Round1Secret<C>, Round1Package<C>), Error> {
    let threshold = usize::from(threshold);
    if threshold == 0 || threshold > participants.len() {
        return Err(Error::new());
    }

    let mut sorted = participants.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    if sorted.len() != participants.len() {
        return Err(Error::new());
    }

    let mut coefficients = Vec::with_capacity(threshold);
    for _ in 0..threshold {
        coefficients.push(random_scalar::<C, R>(rng));
    }

    let commitment = commit_coefficients::<C>(&coefficients);

    let mut shares = BTreeMap::new();
    for &participant in participants {
        let x = identifier_scalar::<C>(participant);
        let y = evaluate_polynomial::<C>(&coefficients, &x);
        shares.insert(participant, y);
    }

    Ok((
        Round1Secret { coefficients },
        Round1Package { commitment, shares },
    ))
}
