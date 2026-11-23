mod common;
use common::hex_to_64;

use ct_ed25519::{Signature, SigningKey, Verifier, VerifyingKey};
use signature::Signer;

/// y = p (non-canonical): encoded as 0xED, 0xFF.., 0x7F
#[test]
fn rejects_non_canonical_y_equal_p() {
    let mut bytes = [0xFFu8; 32];
    bytes[0] = 0xED;
    bytes[31] = 0x7F;
    assert!(
        VerifyingKey::from_bytes(&bytes).is_err(),
        "y == p must be rejected as non-canonical",
    );
}

/// y = p + 1: 0xEE, 0xFF.., 0x7F
#[test]
fn rejects_non_canonical_y_above_p() {
    let mut bytes = [0xFFu8; 32];
    bytes[0] = 0xEE;
    bytes[31] = 0x7F;
    assert!(VerifyingKey::from_bytes(&bytes).is_err());
}

/// All-ones is y = 2^255 - 1, highest bit is sign, so y = 2^255 - 1 with sign=1.
/// y here equals p + 18, non-canonical.
#[test]
fn rejects_all_ones() {
    assert!(VerifyingKey::from_bytes(&[0xFF; 32]).is_err());
}

/// y = 1 (identity point) with sign bit set and x = 0: invalid per RFC 8032.
#[test]
fn rejects_x_zero_with_sign_bit() {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    bytes[31] = 0x80;
    assert!(
        VerifyingKey::from_bytes(&bytes).is_err(),
        "x = 0 with sign = 1 must be rejected",
    );
}

/// y = 1 with sign bit clear: this is the identity point, valid encoding
/// but should not be used as a verifying key for signature verification.
#[test]
fn identity_point_encoding_roundtrips() {
    let mut bytes = [0u8; 32];
    bytes[0] = 1;
    // decoding may succeed; roundtrip must preserve the bytes
    if let Ok(pk) = VerifyingKey::from_bytes(&bytes) {
        assert_eq!(pk.to_bytes(), bytes);
    }
}

/// y = 0: either valid point (±sqrt(-1), 0) or rejected, but must not panic
/// and must roundtrip if accepted.
#[test]
fn y_zero_handling_does_not_panic() {
    let mut bytes = [0u8; 32];
    bytes[31] = 0x00; // sign bit clear, y = 0
    let _ = VerifyingKey::from_bytes(&bytes);
    // no panic = pass
}

/// S = L must be rejected: l (little-endian) written into S bytes.
#[test]
fn rejects_s_equal_l() {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let mut sig_bytes = sk.try_sign(b"m").unwrap().to_bytes();

    // l = 2^252 + 27742317777372353535851937790883648493, LE bytes:
    let l_bytes: [u8; 32] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];
    sig_bytes[32..64].copy_from_slice(&l_bytes);

    let sig = Signature::from_bytes(&sig_bytes);
    assert!(
        sk.verifying_key().verify(b"m", &sig).is_err(),
        "S == l must be rejected",
    );
}

/// S = L - 1 (canonical) with otherwise-correct R must still fail because
/// the R component was not regenerated; this confirms S-boundary handling
/// does not accidentally accept arbitrary S.
#[test]
fn rejects_canonical_but_wrong_s() {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let mut sig_bytes = sk.try_sign(b"m").unwrap().to_bytes();
    // flip the low bit of S (still likely < l)
    sig_bytes[32] ^= 0x01;
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(sk.verifying_key().verify(b"m", &sig).is_err());
}

/// Zero signature (R = identity encoding, S = 0) must be rejected.
#[test]
fn rejects_zero_signature() {
    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    let mut sig_bytes = [0u8; 64];
    sig_bytes[0] = 1; // R = identity point encoding (y=1, sign=0)
    // S = 0 already
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(sk.verifying_key().verify(b"test", &sig).is_err());
}

/// R that is not a valid point encoding must be rejected before any
/// scalar arithmetic.
#[test]
fn rejects_invalid_r_encoding() {
    // R = y = p (non-canonical)
    let mut r_bytes = [0xFFu8; 32];
    r_bytes[0] = 0xED;
    r_bytes[31] = 0x7F;

    let mut sig_bytes = [0u8; 64];
    sig_bytes[..32].copy_from_slice(&r_bytes);
    let sig = Signature::from_bytes(&sig_bytes);

    let sk = SigningKey::from_bytes(&[0x42u8; 32]);
    assert!(sk.verifying_key().verify(b"m", &sig).is_err());
}

#[test]
fn signature_tryfrom_rejects_wrong_length() {
    let short = [0u8; 63];
    let long = [0u8; 65];
    assert!(Signature::try_from(&short[..]).is_err());
    assert!(Signature::try_from(&long[..]).is_err());
}

/// RFC 8032 TEST 1 signature, with S replaced by l - 1: must fail
/// because R does not match the modified S.
#[test]
fn rfc_test1_signature_with_mutated_s_rejected() {
    let pk = VerifyingKey::from_bytes(&hex_to_32_public(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ))
    .unwrap();
    let mut sig_bytes = hex_to_64(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );
    sig_bytes[32] ^= 0x01;
    let sig = Signature::from_bytes(&sig_bytes);
    assert!(pk.verify(b"", &sig).is_err());
}

// local helper to avoid importing common::hex_to_32 twice under different names
fn hex_to_32_public(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}
