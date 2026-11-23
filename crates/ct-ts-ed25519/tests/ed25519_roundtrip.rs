//! End-to-end check that a FROST threshold signature produced through the
//! `ct-ts` protocol verifies with the plain Ed25519 verifier from
//! `ct-ed25519`.

use std::collections::BTreeMap;

use ct_ed25519::{Signature, Verifier, VerifyingKey};
use ct_ts::{
    Ciphersuite, KeyPackage, PartyId, PublicKeyPackage, aggregate, dkg_part1, dkg_part2,
    sign_part1, sign_part2,
};
use ct_ts_ed25519::Ed25519Sha512;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn participants(count: u16) -> Vec<PartyId> {
    (1..=count).map(|id| PartyId::new(id).unwrap()).collect()
}

fn run_dkg(
    threshold: u16,
    participants: &[PartyId],
    rng: &mut StdRng,
) -> (
    BTreeMap<PartyId, KeyPackage<Ed25519Sha512>>,
    PublicKeyPackage<Ed25519Sha512>,
) {
    let mut secrets = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for &id in participants {
        let (secret, package) =
            dkg_part1::<Ed25519Sha512, _>(rng, threshold, participants).unwrap();
        secrets.insert(id, secret);
        round1.insert(id, package);
    }

    let mut key_packages = BTreeMap::new();
    let mut public_package = None;
    for &id in participants {
        let secret = secrets.remove(&id).unwrap();
        let (key_package, public) = dkg_part2::<Ed25519Sha512>(secret, id, &round1).unwrap();
        key_packages.insert(id, key_package);
        public_package = Some(public);
    }

    (key_packages, public_package.unwrap())
}

#[test]
fn frost_signature_verifies_as_plain_ed25519() {
    let participants = participants(3);
    let mut rng = StdRng::seed_from_u64(0x5eed);
    let (key_packages, public_package) = run_dkg(2, &participants, &mut rng);

    let signers = [participants[0], participants[2]];
    let message = b"FROST(Ed25519) threshold signature";

    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &id in &signers {
        let (nonce, commitment) = sign_part1::<Ed25519Sha512, _>(&mut rng, &key_packages[&id]);
        nonces.insert(id, nonce);
        commitments.insert(id, commitment);
    }

    let mut shares = BTreeMap::new();
    for &id in &signers {
        let share = sign_part2::<Ed25519Sha512>(
            nonces.remove(&id).unwrap(),
            &key_packages[&id],
            message,
            &commitments,
        )
        .unwrap();
        shares.insert(id, share);
    }

    let signature: Signature =
        aggregate::<Ed25519Sha512>(message, &public_package, &commitments, &shares).unwrap();

    let public_key_bytes: [u8; 32] =
        Ed25519Sha512::serialize_point(&public_package.group_public_key)
            .try_into()
            .unwrap();
    let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();

    verifying_key.verify(message, &signature).unwrap();
    assert!(
        verifying_key
            .verify(b"a different message", &signature)
            .is_err()
    );
}
