//! Opaque protocol error.

use core::fmt;

/// Opaque threshold-signature error.
///
/// The protocol deliberately exposes no error variants: detailed failures can
/// leak which participant or which secret-dependent check failed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Error(());

impl Error {
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("threshold signature operation failed")
    }
}

impl core::error::Error for Error {}
