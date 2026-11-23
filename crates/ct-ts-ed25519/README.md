# ct-ts-ed25519

The FROST(Ed25519, SHA-512) ciphersuite for [`ct-ts`]. It binds the generic
FROST protocol in `ct-ts` to the concrete Ed25519 types and SHA-512 hash
functions in [`ct-ed25519`], producing signatures that verify as ordinary
Ed25519 signatures.

> **Status:** experimental and unaudited. The crate is a wiring layer; its
> security depends on `ct-ts`, `ct-ed25519`, and their constant-time
> arithmetic.

## Design

### Role in the stack

`ct-ts` implements RFC 9591 without knowing which curve it runs on.
`ct-ts-ed25519` is the small adapter that supplies Ed25519's scalar field,
group, encodings, and hashes:

```text
ct-ts (FROST protocol core)
   │  Ciphersuite
   ▼
ct-ts-ed25519 (Ed25519Sha512)
   ├── ct-ed25519  scalar, point, signing key, verifier
   └── sha2        SHA-512
```

The entire crate is one marker type, `Ed25519Sha512`, implementing
`ct_ts::Ciphersuite`.

### Associated types and constants

| `Ciphersuite` item | Value |
|---|---|
| `Scalar` | `ct_ed25519::Ed25519Scalar` |
| `Point` | `ct_ed25519::Ed25519Point` |
| `Affine` | `ct_ed25519::Ed25519Affine` |
| `Signature` | `ct_ed25519::Signature` |
| `LIMBS` | `4` (the scalar modulus has four 64-bit limbs) |
| `ID` | `"FROST-ED25519-SHA512-v1"` |

### Ed25519 parameters

The base field and group order are

$$
p = 2^{255} - 19,
\qquad
\ell = 2^{252} + 27742317777372353535851937790883648493.
$$

Scalars live in $\mathbb{F}_\ell$; points are twisted Edwards points over
$\mathbb{F}_p$. Compressed points are 32 bytes, and scalars are encoded as 32
little-endian bytes.

### Hash functions

All hashes use SHA-512 and the RFC 9591 context string
$c = \texttt{"FROST-ED25519-SHA512-v1"}$:

$$
\begin{aligned}
H_1(m) &= \operatorname{SHA512}(c \parallel \texttt{"rho"} \parallel m) \bmod \ell,\\
H_2(m) &= \operatorname{SHA512}(m) \bmod \ell,\\
H_3(m) &= \operatorname{SHA512}(c \parallel \texttt{"nonce"} \parallel m) \bmod \ell,\\
H_4(m) &= \operatorname{SHA512}(c \parallel \texttt{"msg"} \parallel m),\\
H_5(m) &= \operatorname{SHA512}(c \parallel \texttt{"com"} \parallel m).
\end{aligned}
$$

$H_2$ deliberately has **no** FROST prefix. The aggregated signature is the
standard Ed25519 pair $(R, z)$ with

$$
zG = R + H_2(R \parallel Y \parallel m)\,Y,
$$

so any RFC 8032 verifier accepts it.

### Module layout

| File | Responsibility |
|---|---|
| `src/lib.rs` | `Ed25519Sha512` and its complete `Ciphersuite` implementation |
| `tests/ed25519_roundtrip.rs` | End-to-end DKG → threshold sign → plain Ed25519 verification |

## Usage

Within this workspace, use path dependencies:

```toml
[dependencies]
ct-ts = { path = "../ct-ts" }
ct-ts-ed25519 = { path = "../ct-ts-ed25519" }
```

The ciphersuite is stateless; select it as a type parameter:

```rust
use ct_ts::Ciphersuite;
use ct_ts_ed25519::Ed25519Sha512;

let generator = Ed25519Sha512::basepoint();
let two = Ed25519Sha512::scalar_from_u64(2);

assert!(bool::from(Ed25519Sha512::ct_eq(
    &Ed25519Sha512::mul_base(&two),
    &Ed25519Sha512::add(&generator, &generator),
)));
```

### End-to-end threshold signature

This follows the flow in `tests/ed25519_roundtrip.rs`: three participants,
threshold two, then verify the result with the plain Ed25519 verifier.

```rust
use std::collections::BTreeMap;

use ct_ed25519::{Verifier, VerifyingKey};
use ct_ts::{
    Ciphersuite, PartyId, aggregate, dkg_part1, dkg_part2, sign_part1, sign_part2,
};
use ct_ts_ed25519::Ed25519Sha512;
use rand::{SeedableRng, rngs::StdRng};

let participants: Vec<PartyId> =
    (1..=3).map(|id| PartyId::new(id).unwrap()).collect();
let mut rng = StdRng::seed_from_u64(7);

// Round 1: each participant samples its DKG polynomial and publishes commitments.
let mut secrets = BTreeMap::new();
let mut round1 = BTreeMap::new();
for &id in &participants {
    let (secret, package) =
        dkg_part1::<Ed25519Sha512, _>(&mut rng, 2, &participants).unwrap();
    secrets.insert(id, secret);
    round1.insert(id, package);
}

// Round 2: verify shares and build the key packages.
let mut key_packages = BTreeMap::new();
let mut public_package = None;
for &id in &participants {
    let (key_package, public) =
        dkg_part2::<Ed25519Sha512>(secrets.remove(&id).unwrap(), id, &round1)
            .unwrap();
    key_packages.insert(id, key_package);
    public_package = Some(public);
}
let public_package = public_package.unwrap();

// Choose any two signers.
let signers = [participants[0], participants[2]];
let message = b"FROST(Ed25519, SHA-512) threshold signature";

// Signing round 1: nonces and commitments.
let mut nonces = BTreeMap::new();
let mut commitments = BTreeMap::new();
for &id in &signers {
    let (nonce, commitment) =
        sign_part1::<Ed25519Sha512, _>(&mut rng, &key_packages[&id]);
    nonces.insert(id, nonce);
    commitments.insert(id, commitment);
}

// Signing round 2: signature shares.
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

// Aggregate into a plain Ed25519 signature.
let signature =
    aggregate::<Ed25519Sha512>(message, &public_package, &commitments, &shares)
        .unwrap();

// Serialize the group key and verify with ct-ed25519.
let public_key_bytes: [u8; 32] =
    Ed25519Sha512::serialize_point(&public_package.group_public_key)
        .try_into()
        .unwrap();
let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();
verifying_key.verify(message, &signature).unwrap();
```

## API reference

### `Ed25519Sha512`

A zero-sized marker type deriving `Clone`, `Copy`, `PartialEq`, and `Debug`.
It implements [`ct_ts::Ciphersuite`] as follows.

| Group | Methods |
|---|---|
| Hash roles | `H1`, `H2`, `H3`, `H4`, `H5` |
| Scalar arithmetic | `scalar_zero`, `scalar_one`, `scalar_add`, `scalar_sub`, `scalar_mul`, `scalar_invert`, `scalar_from_wide`, `scalar_from_u64` |
| Group arithmetic | `basepoint`, `identity`, `add`, `mul`, `mul_base` |
| Constant-time tests | `ct_eq`, `ct_is_identity` |
| Conversions | `to_affine`, `point_from_affine` |
| Serialization | `serialize_affine` (32-byte compressed point), `serialize_scalar` (32-byte little-endian scalar), `serialize_point` (provided default) |
| Signature assembly | `signature(r, z)` → 32-byte compressed $R$ followed by 32-byte little-endian $z$ |

### Re-exported types

The associated types are the public types from `ct-ed25519`:

- `Ed25519Scalar` — scalar field element
- `Ed25519Point` — projective point
- `Ed25519Affine` — affine point
- `Signature` — Ed25519 signature, also accepted by `VerifyingKey`

## Feature flags

The crate defines no features. It depends on `ct-ed25519` with its `zeroize`
feature enabled, so signing keys and secret scalars are zeroized on drop.

## Tests

`tests/ed25519_roundtrip.rs` runs DKG for three participants with threshold
two, signs with two participants, aggregates the shares, and verifies the
result with `ct_ed25519::VerifyingKey`. It also checks that verification fails
for a different message.

```sh
cargo test -p ct-ts-ed25519
```

## Security notes

- Not audited; do not use for production secrets without review.
- Nonces must never be reused. Discard `SigningNonces` after use.
- The ciphersuite does not perform subgroup validation on decoded points;
  protocols that accept untrusted encodings must add it.
- Aggregation does not identify a misbehaving signer. Verify the final
  signature before publishing it.

## License

Licensed under either of MIT or Apache-2.0, at your option.
