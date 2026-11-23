#![no_std]
#![forbid(unsafe_code)]

//! FROST(Ed25519, SHA-512) ciphersuite for `ct-ts`.
//! This crate is a thin wiring layer that binds the generic FROST protocol
//! in `ct-ts` to the concrete types and hash functions of Ed25519.

extern crate alloc;

use alloc::vec::Vec;

use ct_ed25519::{
    CurvePoint, Ed25519Affine, Ed25519Curve, Ed25519Point, Ed25519Scalar, PointEncoding,
    PrimeField, ProjectiveCurvePoint, ScalarField, ScalarMul, Signature as Ed25519Signature,
};
use ct_ts::Ciphersuite;
use sha2::{Digest, Sha512};
use subtle::{Choice, ConstantTimeEq};

/// The FROST(Ed25519, SHA-512) ciphersuite marker type.
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Ed25519Sha512;

impl Ciphersuite for Ed25519Sha512 {
    type Scalar = Ed25519Scalar;
    type Point = Ed25519Point;
    type Affine = Ed25519Affine;
    type Signature = Ed25519Signature;

    const LIMBS: usize = 4;
    const ID: &'static str = "FROST-ED25519-SHA512-v1";

    /// H1: binding-factor hash.
    /// RFC 9591: H1(m) = SHA-512(contextString || "rho" || m) mod L
    fn H1(message: &[u8]) -> Self::Scalar {
        let mut hasher = Sha512::new();
        hasher.update(Self::ID.as_bytes());
        hasher.update(b"rho");
        hasher.update(message);
        // from_bytes_wide reduces the 64-byte digest modulo L (little-endian).
        Ed25519Scalar::from_bytes_wide(&hasher.finalize())
    }

    /// H2: hash to scalar for the signature challenge.
    /// RFC 9591: H2(m) = SHA-512(m) mod L
    /// The FROST(Ed25519) ciphersuite deliberately omits a domain separator
    /// in H2 to maintain compatibility with standard Ed25519 verification.
    fn H2(message: &[u8]) -> Self::Scalar {
        Ed25519Scalar::from_bytes_wide(&Sha512::digest(message))
    }

    /// H3: nonce-derivation hash.
    /// RFC 9591: H3(m) = SHA-512(contextString || "nonce" || m) mod L
    fn H3(message: &[u8]) -> Self::Scalar {
        let mut hasher = Sha512::new();
        hasher.update(Self::ID.as_bytes());
        hasher.update(b"nonce");
        hasher.update(message);
        Ed25519Scalar::from_bytes_wide(&hasher.finalize())
    }

    /// H4: message prehash.
    /// RFC 9591: H4(m) = SHA-512(contextString || "msg" || m)
    fn H4(message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(Self::ID.as_bytes());
        hasher.update(b"msg");
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    /// H5: commitment-list prehash.
    /// RFC 9591: H5(m) = SHA-512(contextString || "com" || m)
    fn H5(message: &[u8]) -> Vec<u8> {
        let mut hasher = Sha512::new();
        hasher.update(Self::ID.as_bytes());
        hasher.update(b"com");
        hasher.update(message);
        hasher.finalize().to_vec()
    }

    fn scalar_zero() -> Self::Scalar {
        Ed25519Scalar::zero()
    }

    fn scalar_one() -> Self::Scalar {
        Ed25519Scalar::one()
    }

    fn scalar_add(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.add(rhs)
    }

    fn scalar_sub(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.sub(rhs)
    }

    fn scalar_mul(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.mul(rhs)
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn scalar_from_wide(bytes: &[u8]) -> Self::Scalar {
        Ed25519Scalar::from_bytes_wide(bytes)
    }

    fn basepoint() -> Self::Point {
        Ed25519Point::basepoint()
    }

    fn identity() -> Self::Point {
        Ed25519Point::identity()
    }

    fn add(lhs: &Self::Point, rhs: &Self::Point) -> Self::Point {
        lhs.add(rhs)
    }

    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        Ed25519Curve::mul(point, scalar)
    }

    fn mul_base(scalar: &Self::Scalar) -> Self::Point {
        Ed25519Curve::mul_base(scalar)
    }

    fn ct_eq(lhs: &Self::Point, rhs: &Self::Point) -> Choice {
        lhs.ct_eq(rhs)
    }

    fn ct_is_identity(point: &Self::Point) -> Choice {
        point.ct_is_identity()
    }

    fn to_affine(point: &Self::Point) -> Self::Affine {
        point.to_affine()
    }

    fn point_from_affine(point: &Self::Affine) -> Self::Point {
        Ed25519Point::from_affine(point)
    }

    fn serialize_affine(point: &Self::Affine) -> Vec<u8> {
        let mut bytes = [0u8; Ed25519Affine::COMPRESSED_LEN];
        point.to_compressed(&mut bytes);
        bytes.to_vec()
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.to_bytes().to_vec()
    }

    fn scalar_from_u64(value: u64) -> Self::Scalar {
        Ed25519Scalar::from_bytes_mod_order(&value.to_le_bytes())
    }

    fn signature(r: &Self::Affine, z: &Self::Scalar) -> Self::Signature {
        let mut bytes = [0u8; Ed25519Signature::BYTE_SIZE];
        r.to_compressed(&mut bytes[..32]);
        bytes[32..].copy_from_slice(&z.to_bytes());
        Ed25519Signature::from_bytes(&bytes)
    }
}
