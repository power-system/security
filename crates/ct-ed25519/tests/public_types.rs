//! Verifies that the curve and scalar types are usable from another crate.

use ct_ed25519::{Ed25519Affine, Ed25519Curve, Ed25519Point, Ed25519Scalar};
use ct_ed25519::{PointEncoding, ProjectiveCurvePoint, ScalarField, ScalarMul};
use subtle::ConstantTimeEq;

const BASEPOINT_COMPRESSED: [u8; 32] = [
    0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
    0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
];

#[test]
fn public_types_are_usable_from_outside_the_crate() {
    let basepoint: Ed25519Point = Ed25519Point::basepoint();
    let affine: Ed25519Affine = basepoint.to_affine();

    let mut encoded = [0u8; 32];
    affine.to_compressed(&mut encoded);
    assert_eq!(encoded, BASEPOINT_COMPRESSED);

    let decoded = Ed25519Affine::from_compressed(&encoded).unwrap();
    let mut original_uncompressed = [0u8; 64];
    let mut decoded_uncompressed = [0u8; 64];
    affine.to_uncompressed(&mut original_uncompressed);
    decoded.to_uncompressed(&mut decoded_uncompressed);
    assert_eq!(original_uncompressed, decoded_uncompressed);

    let reprojected = Ed25519Point::from_affine(&decoded).to_affine();
    assert!(bool::from(reprojected.ct_eq(&affine)));

    let scalar = Ed25519Scalar::from_bytes_mod_order(&[7u8; 32]);
    let scalar_bytes = scalar.to_bytes();
    assert_eq!(
        Ed25519Scalar::from_canonical_bytes(&scalar_bytes)
            .unwrap()
            .to_bytes(),
        scalar_bytes
    );

    let multiplied: Ed25519Point = Ed25519Curve::mul_base(&scalar);
    let expected = Ed25519Curve::mul(&basepoint, &scalar);
    assert!(bool::from(
        multiplied.to_affine().ct_eq(&expected.to_affine())
    ));
}
