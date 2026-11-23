//! Key material produced by distributed key generation.

use alloc::collections::BTreeMap;

use zeroize::ZeroizeOnDrop;

use crate::{Ciphersuite, PartyId};

/// Private key material for one participant.
///
/// This is the only secret-bearing key struct exposed after DKG. The signing
/// share is wiped when the package is dropped.
#[derive(ZeroizeOnDrop)]
pub struct KeyPackage<C: Ciphersuite> {
    /// This participant's identifier.
    #[zeroize(skip)]
    pub identifier: PartyId,

    /// This participant's secret signing share.
    pub signing_share: C::Scalar,

    /// Public key share corresponding to `signing_share`.
    #[zeroize(skip)]
    pub verifying_share: C::Point,

    /// Group public key.
    ///
    /// It is included here because the second signing round needs it for the
    /// RFC 9591 binding factors and challenge. It is public data.
    #[zeroize(skip)]
    pub group_public_key: C::Point,
}

/// Public group information shared by every participant.
#[derive(Clone)]
pub struct PublicKeyPackage<C: Ciphersuite> {
    /// Group public key.
    pub group_public_key: C::Point,

    /// Public key share for every participant.
    pub verifying_shares: BTreeMap<PartyId, C::Point>,
}
