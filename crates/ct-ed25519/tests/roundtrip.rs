mod common;

use ct_ed25519::{Signature, SigningKey, Verifier, VerifyingKey};
use signature::Signer;

fn deterministic_seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

#[test]
fn sign_verify_roundtrip_many_messages() {
    let seeds = [
        deterministic_seed(0x01),
        deterministic_seed(0x42),
        deterministic_seed(0xFF),
    ];
    let messages: &[&[u8]] = &[b"", b"a", b"hello, world", &[0u8; 64], &[0xFFu8; 128]];

    for seed in &seeds {
        let sk = SigningKey::from_bytes(seed);
        let pk = *sk.verifying_key();
        for msg in messages {
            let sig = sk.try_sign(msg).unwrap();
            assert!(
                pk.verify(msg, &sig).is_ok(),
                "roundtrip failed for seed {:?}",
                seed[0]
            );
        }
    }
}

#[test]
fn signature_is_deterministic() {
    let sk = SigningKey::from_bytes(&deterministic_seed(0x42));
    let sig1 = sk.try_sign(b"deterministic message").unwrap();
    let sig2 = sk.try_sign(b"deterministic message").unwrap();
    assert_eq!(sig1.to_bytes(), sig2.to_bytes());
}

#[test]
fn different_messages_produce_different_signatures() {
    let sk = SigningKey::from_bytes(&deterministic_seed(0x11));
    let s1 = sk.try_sign(b"message-a").unwrap();
    let s2 = sk.try_sign(b"message-b").unwrap();
    assert_ne!(s1.to_bytes(), s2.to_bytes());
}

#[test]
fn different_keys_produce_different_public_keys() {
    let sk1 = SigningKey::from_bytes(&deterministic_seed(0x01));
    let sk2 = SigningKey::from_bytes(&deterministic_seed(0x02));
    assert_ne!(
        sk1.verifying_key().to_bytes(),
        sk2.verifying_key().to_bytes()
    );
}

#[test]
fn signing_key_roundtrip_via_to_bytes() {
    let seed = deterministic_seed(0x77);
    let sk1 = SigningKey::from_bytes(&seed);
    let seed_bytes = sk1.to_bytes();
    assert_eq!(seed_bytes, seed, "to_bytes must return the original seed");

    let sk2 = SigningKey::from_bytes(&seed_bytes);
    assert_eq!(
        sk1.verifying_key().to_bytes(),
        sk2.verifying_key().to_bytes(),
    );
}

#[test]
fn verifying_key_bytes_roundtrip() {
    let sk = SigningKey::from_bytes(&deterministic_seed(0x42));
    let pk = sk.verifying_key();
    let bytes = pk.to_bytes();
    let pk2 = VerifyingKey::from_bytes(&bytes).unwrap();
    assert_eq!(bytes, pk2.to_bytes());
}

#[test]
fn signature_bytes_roundtrip() {
    let sk = SigningKey::from_bytes(&deterministic_seed(0x99));
    let sig = sk.try_sign(b"x").unwrap();
    let bytes = sig.to_bytes();
    let sig2 = Signature::from_bytes(&bytes);
    assert_eq!(bytes, sig2.to_bytes());
    assert!(sk.verifying_key().verify(b"x", &sig2).is_ok());
}

#[test]
fn signature_ct_eq_is_reflexive() {
    use subtle::ConstantTimeEq;
    let sk = SigningKey::from_bytes(&deterministic_seed(0x33));
    let sig = sk.try_sign(b"m").unwrap();
    assert!(bool::from(sig.ct_eq(&sig)));
}
