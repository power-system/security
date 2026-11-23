//! Public participant identifiers.

use core::num::NonZeroU16;

use crate::Error;

/// Non-zero participant identifier.
///
/// This value is the `x_i` used by Lagrange interpolation and by the FROST
/// binding-factor computation. It is always public.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PartyId(NonZeroU16);

impl PartyId {
    /// Construct a participant identifier. Zero is rejected.
    pub fn new(value: u16) -> Option<Self> {
        NonZeroU16::new(value).map(Self)
    }

    /// Return the underlying non-zero integer.
    pub const fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u16> for PartyId {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value).ok_or_else(Error::new)
    }
}
