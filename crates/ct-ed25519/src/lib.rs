#![no_std]
#![forbid(unsafe_code)]

mod error;
mod field;
mod keys;
mod point;
mod scalar;
mod sign;
mod signature;
mod verify;

pub use error::SignatureError;
pub use keys::{SigningKey, VerifyingKey};
pub use point::{Ed25519Affine, Ed25519Curve, Ed25519Point};
pub use scalar::Ed25519Scalar;
pub use signature::Signature;

pub use ::signature::{Signer, Verifier};

// Traits needed to operate on the exported curve and scalar types.
pub use ct_curve_point::curve_model::{AffineCurvePoint, ProjectiveCurvePoint};
pub use ct_curve_point::{CurveModel, CurvePoint, PointEncoding, ScalarMul};
pub use ct_fp::PrimeField;
pub use ct_scalar::ScalarField;
