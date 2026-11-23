//! `ct-ts` — the threshold-signature layer of the `ct-*` family.
//!
//! This crate implements FROST (RFC 9591) generically over a
//! [`Ciphersuite`]. It is unconditionally `no_std` and uses only `alloc`.
//! There is deliberately no `std` feature.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ciphersuite;
pub mod dkg;
pub mod error;
pub mod identifier;
pub mod keys;
pub mod lagrange;
pub mod sign;

pub use ciphersuite::Ciphersuite;
pub use dkg::{Round1Package, Round1Secret, dkg_part1, dkg_part2};
pub use error::Error;
pub use identifier::PartyId;
pub use keys::{KeyPackage, PublicKeyPackage};
pub use lagrange::{coefficients, combine_shares};
pub use sign::{SignCommitment, SigningNonces, aggregate, sign_part1, sign_part2};

pub use ct_scalar::ScalarField;
