mod common;
use common::{hex_to_32, hex_to_64, hex_to_vec};

use ct_ed25519::{Signature, SigningKey, Verifier, VerifyingKey};
use signature::Signer;

struct Vector {
    name: &'static str,
    secret: &'static str,
    public: &'static str,
    message: &'static str,
    signature: &'static str,
}

const VECTORS: &[Vector] = &[
    // RFC 8032 §7.1 TEST 1 — empty message
    Vector {
        name: "rfc8032/test1",
        secret: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        public: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        message: "",
        signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    },
    // RFC 8032 §7.1 TEST 2 — one-byte message
    Vector {
        name: "rfc8032/test2",
        secret: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        public: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        message: "72",
        signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    },
    // RFC 8032 §7.1 TEST 3 — two-byte message
    Vector {
        name: "rfc8032/test3",
        secret: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
        public: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
        message: "af82",
        signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
    },
    // RFC 8032 §7.1 TEST SHA(abc)
    Vector {
        name: "rfc8032/sha_abc",
        secret: "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42",
        public: "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
        message: "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
        signature: "dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704",
    },
];

#[test]
fn signing_key_derives_correct_public_key() {
    for v in VECTORS {
        let seed = hex_to_32(v.secret);
        let sk = SigningKey::from_bytes(&seed);
        let pk_hex = hex::encode(sk.verifying_key().to_bytes());
        assert_eq!(pk_hex, v.public, "{}: public key mismatch", v.name);
    }
}

#[test]
fn signature_matches_rfc_vector() {
    for v in VECTORS {
        let seed = hex_to_32(v.secret);
        let sk = SigningKey::from_bytes(&seed);
        let message = hex_to_vec(v.message);
        let sig = sk.try_sign(&message).unwrap();
        assert_eq!(
            hex::encode(sig.to_bytes()),
            v.signature,
            "{}: signature mismatch",
            v.name,
        );
    }
}

#[test]
fn verification_accepts_rfc_vector() {
    for v in VECTORS {
        let pk = VerifyingKey::from_bytes(&hex_to_32(v.public)).unwrap();
        let message = hex_to_vec(v.message);
        let sig = Signature::from_bytes(&hex_to_64(v.signature));
        assert!(
            pk.verify(&message, &sig).is_ok(),
            "{}: verification should succeed",
            v.name,
        );
    }
}

#[test]
fn verification_rejects_tampered_signature() {
    for v in VECTORS {
        let pk = VerifyingKey::from_bytes(&hex_to_32(v.public)).unwrap();
        let message = hex_to_vec(v.message);
        let mut sig_bytes = hex_to_64(v.signature);
        sig_bytes[0] ^= 0x01;
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(
            pk.verify(&message, &sig).is_err(),
            "{}: tampered signature must be rejected",
            v.name,
        );
    }
}

#[test]
fn verification_rejects_tampered_message() {
    for v in VECTORS {
        let pk = VerifyingKey::from_bytes(&hex_to_32(v.public)).unwrap();
        let mut message = hex_to_vec(v.message);
        message.push(0x00);
        let sig = Signature::from_bytes(&hex_to_64(v.signature));
        assert!(
            pk.verify(&message, &sig).is_err(),
            "{}: tampered message must be rejected",
            v.name,
        );
    }
}

#[test]
fn verification_rejects_wrong_public_key() {
    for v in VECTORS {
        let mut wrong = hex_to_32(v.public);
        wrong[0] ^= 0x01;
        let pk = match VerifyingKey::from_bytes(&wrong) {
            Ok(pk) => pk,
            Err(_) => continue, // flipped bit might yield invalid point; skip
        };
        let message = hex_to_vec(v.message);
        let sig = Signature::from_bytes(&hex_to_64(v.signature));
        assert!(
            pk.verify(&message, &sig).is_err(),
            "{}: verification with wrong key must fail",
            v.name,
        );
    }
}
