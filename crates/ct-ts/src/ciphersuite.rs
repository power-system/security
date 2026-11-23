//! The only curve-facing interface in `ct-ts`.
//!
//! The protocol never imports a concrete group implementation. Instead it
//! routes every group operation through this trait. A ciphersuite crate (for
//! example a future `ct-ts-ed25519`) is a thin wiring layer that delegates
//! these methods to its curve types.

use alloc::vec::Vec;
use core::fmt::Debug;

use subtle::Choice;
use zeroize::Zeroize;

/// A FROST ciphersuite.
///
/// The hash functions follow RFC 9591 exactly:
///
/// * `H1` is the binding-factor hash (`rho`).
/// * `H2` is the bare signature-challenge hash. For Ed25519 it must **not**
///   contain a FROST domain separator, so that the resulting signature is
///   verifiable by any RFC 8032 verifier.
/// * `H3` expands fresh randomness plus the secret share into a nonce.
/// * `H4` and `H5` produce the fixed-length message and commitment digests
///   used as inputs to the binding-factor hash.
#[allow(non_snake_case)]
pub trait Ciphersuite: Copy + Clone + PartialEq + Debug {
    /// Scalar field of the group.
    ///
    /// Ciphersuite scalars are expected to implement `ct_scalar::ScalarField`.
    /// The bound is not written here because `ScalarField` is const-generic
    /// and stable Rust cannot use the associated `LIMBS` constant as its const
    /// argument.
    type Scalar: Copy + Clone + Zeroize;

    /// Projective group element. Used for secret-dependent arithmetic.
    type Point: Copy + Clone;

    /// Affine group element. Used for public commitments and encoding.
    type Affine: Copy + Clone;

    /// Canonical signature type produced by [`crate::aggregate`].
    type Signature;

    /// Number of 64-bit limbs in the scalar modulus.
    const LIMBS: usize;

    /// RFC 9591 context string, for example `"FROST-ED25519-SHA512-v1"`.
    const ID: &'static str;

    /// Binding-factor hash: `H(contextString || "rho" || message)`.
    fn H1(message: &[u8]) -> Self::Scalar;

    /// Ed25519-compatible challenge hash: `H(message)` with no FROST prefix.
    fn H2(message: &[u8]) -> Self::Scalar;

    /// Nonce-derivation hash: `H(contextString || "nonce" || message)`.
    fn H3(message: &[u8]) -> Self::Scalar;

    /// Message prehash: `H(contextString || "msg" || message)`.
    fn H4(message: &[u8]) -> Vec<u8>;

    /// Commitment-list prehash: `H(contextString || "com" || message)`.
    fn H5(message: &[u8]) -> Vec<u8>;

    /// Additive identity in the scalar field.
    fn scalar_zero() -> Self::Scalar;

    /// Multiplicative identity in the scalar field.
    fn scalar_one() -> Self::Scalar;

    /// Scalar addition.
    fn scalar_add(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar;

    /// Scalar subtraction.
    fn scalar_sub(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar;

    /// Scalar multiplication.
    fn scalar_mul(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar;

    /// Scalar inversion.
    ///
    /// This is only used on public identifiers by [`crate::lagrange`].
    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar;

    /// Interpret a wide byte string as a scalar by reducing it modulo the
    /// group order.
    fn scalar_from_wide(bytes: &[u8]) -> Self::Scalar;

    /// Group generator.
    fn basepoint() -> Self::Point;

    /// Group identity.
    fn identity() -> Self::Point;

    /// Group addition.
    fn add(lhs: &Self::Point, rhs: &Self::Point) -> Self::Point;

    /// Scalar multiplication of an arbitrary point.
    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point;

    /// Scalar multiplication of the generator.
    fn mul_base(scalar: &Self::Scalar) -> Self::Point;

    /// Constant-time point equality.
    fn ct_eq(lhs: &Self::Point, rhs: &Self::Point) -> Choice;

    /// Constant-time identity test.
    fn ct_is_identity(point: &Self::Point) -> Choice;

    /// Convert a projective point to affine form.
    fn to_affine(point: &Self::Point) -> Self::Affine;

    /// Embed an affine point into the projective representation.
    fn point_from_affine(point: &Self::Affine) -> Self::Point;

    /// Canonical encoding of an affine point.
    fn serialize_affine(point: &Self::Affine) -> Vec<u8>;

    /// Canonical encoding of a scalar.
    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8>;

    /// Convert a small integer into the scalar field.
    ///
    /// This is used for party identifiers and Lagrange interpolation, never for
    /// secret material.
    fn scalar_from_u64(value: u64) -> Self::Scalar;

    /// Assemble the ciphersuite's canonical signature from `R` and `z`.
    fn signature(r: &Self::Affine, z: &Self::Scalar) -> Self::Signature;

    /// Canonical encoding of a point.
    fn serialize_point(point: &Self::Point) -> Vec<u8> {
        Self::serialize_affine(&Self::to_affine(point))
    }
}
