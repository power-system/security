//! A toy ciphersuite used to exercise the protocol end-to-end without adding a
//! real curve dependency to the core crate.
//!
//! Scalars and group elements both live in the additive group modulo the prime
//! `2^61 - 1`. This is obviously not secure, but it satisfies the algebraic
//! equations that FROST relies on, so it catches protocol wiring bugs.

use std::collections::BTreeMap;

use ct_ts::{
    Ciphersuite, PartyId, aggregate, coefficients, combine_shares, dkg_part1, dkg_part2,
    sign_part1, sign_part2,
};
use rand_core::{Infallible, TryCryptoRng, TryRng};
use subtle::Choice;
use zeroize::Zeroize;

const P: u64 = (1u64 << 61) - 1;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ToyScalar(u64);

impl ToyScalar {
    fn new(value: u64) -> Self {
        Self(value % P)
    }
}

impl Zeroize for ToyScalar {
    fn zeroize(&mut self) {
        self.0 = 0;
    }
}

impl ToyScalar {
    fn add(self, rhs: Self) -> Self {
        Self((self.0 + rhs.0) % P)
    }

    fn sub(self, rhs: Self) -> Self {
        Self((self.0 + P - rhs.0) % P)
    }

    fn mul(self, rhs: Self) -> Self {
        Self(((self.0 as u128 * rhs.0 as u128) % P as u128) as u64)
    }

    fn invert(self) -> Self {
        Self(pow_mod(self.0 as u128, P - 2) as u64)
    }
}

fn pow_mod(mut base: u128, mut exponent: u64) -> u128 {
    let modulus = P as u128;
    let mut result = 1u128;
    base %= modulus;
    while exponent > 0 {
        if exponent & 1 == 1 {
            result = result * base % modulus;
        }
        base = base * base % modulus;
        exponent >>= 1;
    }
    result
}

fn hash64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct ToySuite;

impl Ciphersuite for ToySuite {
    type Scalar = ToyScalar;
    type Point = u64;
    type Affine = u64;
    type Signature = [u8; 16];

    const LIMBS: usize = 1;
    const ID: &'static str = "TOY-v1";

    fn H1(message: &[u8]) -> Self::Scalar {
        ToyScalar::new(hash64(message))
    }

    fn H2(message: &[u8]) -> Self::Scalar {
        ToyScalar::new(hash64(message))
    }

    fn H3(message: &[u8]) -> Self::Scalar {
        ToyScalar::new(hash64(message))
    }

    fn H4(message: &[u8]) -> Vec<u8> {
        hash64(message).to_le_bytes().to_vec()
    }

    fn H5(message: &[u8]) -> Vec<u8> {
        hash64(message).to_le_bytes().to_vec()
    }

    fn scalar_zero() -> Self::Scalar {
        ToyScalar(0)
    }

    fn scalar_one() -> Self::Scalar {
        ToyScalar(1)
    }

    fn scalar_add(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.add(*rhs)
    }

    fn scalar_sub(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.sub(*rhs)
    }

    fn scalar_mul(lhs: &Self::Scalar, rhs: &Self::Scalar) -> Self::Scalar {
        lhs.mul(*rhs)
    }

    fn scalar_invert(scalar: &Self::Scalar) -> Self::Scalar {
        scalar.invert()
    }

    fn scalar_from_wide(bytes: &[u8]) -> Self::Scalar {
        let mut accumulator: u128 = 0;
        for byte in bytes {
            accumulator = (accumulator * 256 + u128::from(*byte)) % u128::from(P);
        }
        ToyScalar(accumulator as u64)
    }

    fn basepoint() -> Self::Point {
        1
    }

    fn identity() -> Self::Point {
        0
    }

    fn add(lhs: &Self::Point, rhs: &Self::Point) -> Self::Point {
        (lhs + rhs) % P
    }

    fn mul(point: &Self::Point, scalar: &Self::Scalar) -> Self::Point {
        ((u128::from(*point) * u128::from(scalar.0)) % u128::from(P)) as u64
    }

    fn mul_base(scalar: &Self::Scalar) -> Self::Point {
        scalar.0
    }

    fn ct_eq(lhs: &Self::Point, rhs: &Self::Point) -> Choice {
        Choice::from(u8::from(lhs == rhs))
    }

    fn ct_is_identity(point: &Self::Point) -> Choice {
        Choice::from(u8::from(*point == 0))
    }

    fn to_affine(point: &Self::Point) -> Self::Affine {
        *point
    }

    fn point_from_affine(point: &Self::Affine) -> Self::Point {
        *point
    }

    fn serialize_affine(point: &Self::Affine) -> Vec<u8> {
        point.to_le_bytes().to_vec()
    }

    fn serialize_scalar(scalar: &Self::Scalar) -> Vec<u8> {
        scalar.0.to_le_bytes().to_vec()
    }

    fn scalar_from_u64(value: u64) -> Self::Scalar {
        ToyScalar::new(value)
    }

    fn signature(r: &Self::Affine, z: &Self::Scalar) -> Self::Signature {
        let mut signature = [0u8; 16];
        signature[..8].copy_from_slice(&r.to_le_bytes());
        signature[8..].copy_from_slice(&z.0.to_le_bytes());
        signature
    }
}

/// Minimal deterministic RNG for tests.
struct TestRng(u64);

impl TestRng {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
}

impl TryRng for TestRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        Ok(self.next() as u32)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        Ok(self.next())
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in dst.chunks_mut(8) {
            let bytes = self.next().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

impl TryCryptoRng for TestRng {}

fn participants(count: u16) -> Vec<PartyId> {
    (1..=count)
        .map(|value| PartyId::new(value).unwrap())
        .collect()
}

fn run_dkg(
    threshold: u16,
    participants: &[PartyId],
    rng: &mut TestRng,
) -> (
    BTreeMap<PartyId, ct_ts::KeyPackage<ToySuite>>,
    ct_ts::PublicKeyPackage<ToySuite>,
) {
    let mut secrets = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &identifier in participants {
        let (secret, package) = dkg_part1::<ToySuite, _>(rng, threshold, participants).unwrap();
        secrets.insert(identifier, secret);
        round1.insert(identifier, package);
    }

    let mut key_packages = BTreeMap::new();
    let mut public_package = None;
    for &identifier in participants {
        let secret = secrets.remove(&identifier).unwrap();
        let (key_package, public_key_package) =
            dkg_part2::<ToySuite>(secret, identifier, &round1).unwrap();
        key_packages.insert(identifier, key_package);
        public_package = Some(public_key_package);
    }

    (key_packages, public_package.unwrap())
}

fn sign(
    signers: &[PartyId],
    key_packages: &BTreeMap<PartyId, ct_ts::KeyPackage<ToySuite>>,
    public_package: &ct_ts::PublicKeyPackage<ToySuite>,
    message: &[u8],
    rng: &mut TestRng,
) -> [u8; 16] {
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &identifier in signers {
        let (nonce, commitment) = sign_part1::<ToySuite, _>(rng, &key_packages[&identifier]);
        nonces.insert(identifier, nonce);
        commitments.insert(identifier, commitment);
    }

    let mut shares = BTreeMap::new();
    for &identifier in signers {
        let share = sign_part2::<ToySuite>(
            nonces.remove(&identifier).unwrap(),
            &key_packages[&identifier],
            message,
            &commitments,
        )
        .unwrap();
        shares.insert(identifier, share);
    }

    aggregate::<ToySuite>(message, public_package, &commitments, &shares).unwrap()
}

fn verify(signature: &[u8; 16], public_key: &u64, message: &[u8]) -> bool {
    let r = u64::from_le_bytes(signature[..8].try_into().unwrap());
    let z = ToyScalar::new(u64::from_le_bytes(signature[8..].try_into().unwrap()));

    let mut challenge_input = ToySuite::serialize_affine(&r);
    challenge_input.extend_from_slice(&ToySuite::serialize_affine(public_key));
    challenge_input.extend_from_slice(message);
    let challenge = ToySuite::H2(&challenge_input);

    let lhs = ToySuite::mul_base(&z);
    let rhs = ToySuite::add(&r, &ToySuite::mul(public_key, &challenge));
    lhs == rhs
}

#[test]
fn dkg_and_threshold_signature_roundtrip() {
    let participants = participants(5);
    let mut rng = TestRng::new(0x1234_5678);

    let (key_packages, public_package) = run_dkg(3, &participants, &mut rng);

    for &identifier in &participants {
        let key_package = &key_packages[&identifier];
        assert_eq!(key_package.identifier, identifier);
        assert_eq!(
            key_package.group_public_key,
            public_package.group_public_key
        );
        assert_eq!(
            key_package.verifying_share,
            ToySuite::mul_base(&key_package.signing_share)
        );
        assert_eq!(
            public_package.verifying_shares[&identifier],
            key_package.verifying_share
        );
    }

    let signers = [participants[0], participants[2], participants[4]];
    let message = b"threshold signature over a toy group";
    let signature = sign(&signers, &key_packages, &public_package, message, &mut rng);

    assert!(verify(
        &signature,
        &public_package.group_public_key,
        message
    ));
    assert!(!verify(
        &signature,
        &public_package.group_public_key,
        b"other"
    ));
}

#[test]
fn every_threshold_subset_produces_a_valid_signature() {
    let participants = participants(4);
    let mut rng = TestRng::new(99);
    let (key_packages, public_package) = run_dkg(2, &participants, &mut rng);

    for first in 0..participants.len() {
        for second in first + 1..participants.len() {
            let signers = [participants[first], participants[second]];
            let message = b"any two signers work";
            let signature = sign(&signers, &key_packages, &public_package, message, &mut rng);
            assert!(verify(
                &signature,
                &public_package.group_public_key,
                message
            ));
        }
    }
}

#[test]
fn lagrange_combines_signing_shares_to_the_group_key() {
    let participants = participants(3);
    let mut rng = TestRng::new(7);
    let (key_packages, _) = run_dkg(3, &participants, &mut rng);

    let shares: Vec<ToyScalar> = participants
        .iter()
        .map(|identifier| key_packages[identifier].signing_share)
        .collect();
    let coefficients = coefficients::<ToySuite>(&participants);
    let group_secret = combine_shares::<ToySuite>(&shares, &coefficients);

    let group_public_key = key_packages[&participants[0]].group_public_key;
    assert_eq!(ToySuite::mul_base(&group_secret), group_public_key);
}

#[test]
fn dkg_rejects_tampered_shares() {
    let participants = participants(3);
    let mut rng = TestRng::new(11);

    let mut secrets = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &identifier in &participants {
        let (secret, package) = dkg_part1::<ToySuite, _>(&mut rng, 2, &participants).unwrap();
        secrets.insert(identifier, secret);
        round1.insert(identifier, package);
    }

    // Corrupt the share that dealer 2 sends to participant 1.
    round1
        .get_mut(&participants[1])
        .unwrap()
        .shares
        .insert(participants[0], ToyScalar::new(42));

    let secret = secrets.remove(&participants[0]).unwrap();
    assert!(dkg_part2::<ToySuite>(secret, participants[0], &round1).is_err());
}

#[test]
fn dkg_rejects_invalid_parameters() {
    let participants = participants(2);
    let mut rng = TestRng::new(1);

    assert!(dkg_part1::<ToySuite, _>(&mut rng, 0, &participants).is_err());
    assert!(dkg_part1::<ToySuite, _>(&mut rng, 3, &participants).is_err());
    assert!(dkg_part1::<ToySuite, _>(&mut rng, 1, &[]).is_err());

    let duplicate = [participants[0], participants[0]];
    assert!(dkg_part1::<ToySuite, _>(&mut rng, 1, &duplicate).is_err());
}

#[test]
fn zero_party_id_is_rejected() {
    assert!(PartyId::new(0).is_none());
    assert_eq!(
        PartyId::try_from(0).unwrap_err().to_string(),
        "threshold signature operation failed"
    );
}
