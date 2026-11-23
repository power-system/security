# ct-ts

A `no_std` implementation of the **FROST** two-round threshold Schnorr
signature protocol ([RFC 9591]), structured as a curve-agnostic protocol core.

`ct-ts` contains all protocol logic — distributed key generation, threshold
signing, aggregation, and Lagrange interpolation — and leaves the group and
hash implementation behind a single [`Ciphersuite`] trait. A concrete
ciphersuite crate wires that trait to a curve without reimplementing FROST.

> **Status:** experimental, v0.1.5. The protocol core has not been
> independently audited. Do not use it to protect production secrets without a
> security review.

## Scope

**Implemented**

- Two-round distributed key generation using Pedersen VSS
- Two-round FROST signing and signature-share aggregation
- Lagrange interpolation, with public coefficients separated from secret-share
  combination
- RFC 9591 hash roles `H1`–`H5`
- Constant-time secret-share arithmetic through the [`ct-scalar`] stack
- Zeroization of signing shares and nonces on drop
- `#![no_std]` + `alloc`; there is deliberately no `std` feature

**Not included**

- Networking, serialization, or a transport format
- Preprocessing / nonce precomputation
- Identifiable abort
- A concrete Ed25519 ciphersuite in this crate
- FIPS compliance

A curve-specific crate (for example a future `ct-ts-ed25519`) provides the
`Ciphersuite` implementation. `ct-ts` itself depends only on [`ct-scalar`],
[`subtle`], [`zeroize`], and [`rand_core`].

## Architecture

```text
ct-ts/
├── src/
│   ├── lib.rs              # #![no_std], extern crate alloc
│   ├── ciphersuite.rs      # Ciphersuite trait: the only curve-facing seam
│   ├── identifier.rs       # PartyId: NonZeroU16
│   ├── error.rs            # opaque Error
│   ├── lagrange.rs         # coefficients() + combine_shares()
│   ├── keys.rs             # KeyPackage, PublicKeyPackage
│   ├── dkg/
│   │   ├── round1.rs       # dkg_part1()
│   │   └── round2.rs       # dkg_part2()
│   └── sign/
│       ├── round1.rs       # sign_part1()
│       └── round2.rs       # sign_part2(), aggregate()
└── tests/
    └── toy_protocol.rs     # end-to-end tests with a toy group
```

Every protocol module is generic over `C: Ciphersuite`; none imports a
concrete curve. The seam covers scalar arithmetic, group operations, point and
scalar encoding, and the RFC 9591 hash functions.

## Protocol

### Distributed key generation

For a signing set of size `n` and a threshold `t` (the minimum number of
signers), each dealer `j` samples a secret polynomial of degree `t - 1`:

$$
f_j(x) = a_{j,0} + a_{j,1}x + \cdots + a_{j,t-1}x^{t-1}.
$$

The dealer publishes coefficient commitments

$$
C_{j,k} = [a_{j,k}]G,
$$

and sends share $f_j(x_i)$ to participant $i$, where $x_i$ is the participant's
public [`PartyId`]. Each recipient checks

$$
[f_j(x_i)]G = \sum_k [x_i^k] C_{j,k}.
$$

After all valid shares are summed, participant `i` holds

$$
s_i = \sum_j f_j(x_i),
$$

the group public key is

$$
Y = \sum_j C_{j,0},
$$

and the public key share of participant `i` is the evaluation of the summed
commitments at $x_i$.

### Threshold signing

Round 1 generates a hiding/binding nonce pair $(d_i, e_i)$ and broadcasts only
the commitments

$$
D_i = [d_i]G, \qquad E_i = [e_i]G.
$$

Round 2 computes the RFC 9591 binding factor

$$
\rho_i = H_1(Y \;\|\; H_4(M) \;\|\; H_5(\text{commitment list}) \;\|\; i),
$$

the group commitment

$$
R = \sum_{k} \left(D_k + [\rho_k]E_k\right),
$$

the challenge

$$
c = H_2(R \;\|\; Y \;\|\; M),
$$

the Lagrange coefficient

$$
\lambda_i = \prod_{j \ne i} \frac{x_j}{x_j - x_i},
$$

and the signature share

$$
z_i = d_i + \rho_i e_i + c \lambda_i s_i.
$$

The coordinator aggregates

$$
z = \sum_i z_i
$$

and returns the signature $(R, z)$ in the ciphersuite's canonical encoding. For
Ed25519, `H2` must be the bare Ed25519 challenge hash — no FROST domain
separator — so the result verifies under any RFC 8032-compliant verifier.

### Hash roles

| Function | RFC 9591 role |
|---|---|
| `H1` | Binding factor `rho`, with `"rho"` domain separator |
| `H2` | Bare Ed25519 challenge hash, **no** FROST prefix |
| `H3` | Nonce derivation, with `"nonce"` domain separator |
| `H4` | Message prehash, with `"msg"` domain separator |
| `H5` | Commitment-list prehash, with `"com"` domain separator |

## Usage

```toml
[dependencies]
ct-ts = "0.1.5"
```

Within this workspace, use the path dependency
`ct-ts = { path = "../ct-ts" }`. For a ready-made Ed25519 ciphersuite, see
[`ct-ts-ed25519`](../ct-ts-ed25519), which supplies `Ed25519Sha512` and an
end-to-end threshold-signature example.

### Implementing a ciphersuite

A ciphersuite is a small wiring layer. It supplies associated scalar, point,
affine-point, and signature types, plus the operations on them:

```rust
use ct_ts::Ciphersuite;

#[derive(Clone, Copy, PartialEq, Debug)]
struct MySuite;

impl Ciphersuite for MySuite {
    type Scalar = MyScalar;
    type Point = MyPoint;
    type Affine = MyAffine;
    type Signature = MySignature;

    const LIMBS: usize = 4;
    const ID: &'static str = "FROST-MY-CURVE-v1";

    fn H1(message: &[u8]) -> Self::Scalar { /* ... */ }
    fn H2(message: &[u8]) -> Self::Scalar { /* ... */ }
    fn H3(message: &[u8]) -> Self::Scalar { /* ... */ }
    fn H4(message: &[u8]) -> Vec<u8> { /* ... */ }
    fn H5(message: &[u8]) -> Vec<u8> { /* ... */ }

    // Scalar and group operations, encodings, and signature assembly.
    // See `src/ciphersuite.rs` for the complete list.
}
```

### Running the protocol

The snippets below assume a `MySuite` ciphersuite and an
`R: rand_core::Rng + CryptoRng`.

```rust
use std::collections::BTreeMap;
use ct_ts::{
    aggregate, dkg_part1, dkg_part2, sign_part1, sign_part2, PartyId,
};

let participants = [PartyId::new(1).unwrap(), PartyId::new(2).unwrap(),
                    PartyId::new(3).unwrap()];
let threshold = 2;

// DKG round 1: every participant deals a polynomial.
let mut secrets = BTreeMap::new();
let mut round1_packages = BTreeMap::new();
for &id in &participants {
    let (secret, package) =
        dkg_part1::<MySuite, _>(&mut rng, threshold, &participants)?;
    secrets.insert(id, secret);
    round1_packages.insert(id, package);
}

// DKG round 2: verify shares, build key packages.
let mut key_packages = BTreeMap::new();
let mut public_package = None;
for &id in &participants {
    let (key_package, public) = dkg_part2::<MySuite>(
        secrets.remove(&id).unwrap(), id, &round1_packages)?;
    key_packages.insert(id, key_package);
    public_package = Some(public);
}
let public_package = public_package.unwrap();

// Signing round 1: publish nonce commitments.
let signers = [participants[0], participants[2]];
let message = b"message to sign";
let mut nonces = BTreeMap::new();
let mut commitments = BTreeMap::new();
for &id in &signers {
    let (nonce, commitment) =
        sign_part1::<MySuite, _>(&mut rng, &key_packages[&id]);
    nonces.insert(id, nonce);
    commitments.insert(id, commitment);
}

// Signing round 2: produce shares and aggregate.
let mut shares = BTreeMap::new();
for &id in &signers {
    let share = sign_part2::<MySuite>(
        nonces.remove(&id).unwrap(),
        &key_packages[&id],
        message,
        &commitments,
    )?;
    shares.insert(id, share);
}

let signature = aggregate::<MySuite>(
    message, &public_package, &commitments, &shares)?;
```

`KeyPackage` contains the participant's secret signing share and is zeroized
on drop. `Round1Package` contains DKG shares, so it is also zeroized on drop,
but the transport layer is still responsible for confidentiality.

## API overview

| Type / function | Purpose |
|---|---|
| `PartyId` | Non-zero `u16` participant identifier |
| `Ciphersuite` | Curve/hash seam implemented by a ciphersuite crate |
| `dkg_part1(rng, threshold, participants)` | Sample polynomial, commit, distribute shares |
| `dkg_part2(secret, own_id, round1_packages)` | Verify shares, build `KeyPackage` / `PublicKeyPackage` |
| `sign_part1(rng, key_package)` | Generate nonces and publish commitments |
| `sign_part2(nonces, key_package, message, commitments)` | Produce a signature share |
| `aggregate(message, public_key_package, commitments, shares)` | Combine shares into a signature |
| `coefficients(signers)` | Public Lagrange coefficients |
| `combine_shares(shares, coefficients)` | Constant-time secret-share combination |
| `Error` | Opaque protocol error |

`dkg_part1` treats `threshold` as the minimum number of signers, so the
sampled polynomial has degree `threshold - 1`. Invalid thresholds, duplicate
participants, missing packages, and failed share verification return an opaque
`Error`.

## Security notes

- `ct-ts` has **not been audited**.
- `KeyPackage` is the only post-DKG secret-bearing key type. Its signing share
  is zeroized on drop. `SigningNonces` is zeroized on drop.
- Nonces must never be reused. `sign_part1` uses fresh randomness mixed with
  the signing share through `H3`; discarding or reusing `SigningNonces` breaks
  the security guarantee.
- Secret-share arithmetic goes through the ciphersuite's scalar operations.
  The protocol avoids secret-dependent branches, but the Rust compiler is not
  required to preserve constant-time behaviour across all targets. The
  ciphersuite implementation must provide constant-time field and group
  operations.
- `ct-ts` does not validate that points received over a network are in the
  correct prime-order subgroup. That validation belongs to the ciphersuite's
  `deserialize` / `point_from_affine` path.
- `aggregate` does not identify a misbehaving participant; identifiable abort
  is deferred to a later version. Verify the final signature with the
  ciphersuite's verifier before publishing it.
- The current DKG requires the dealer set to equal the participant set. Each
  dealer must include its own package so that the group key includes its
  constant term.

## Testing

The core test suite uses a deliberately insecure toy ciphersuite over the
additive group modulo $2^{61}-1$. It exercises DKG, share verification,
threshold signing, aggregation, Lagrange interpolation, and the standard
Schnorr verification equation without adding a curve dependency to the core
crate.

```sh
cargo test
cargo clippy --all-targets -- -D warnings
```

Real Ed25519 interoperability requires a ciphersuite wiring crate and its
integration tests.

## Dependencies

| Crate | Role |
|---|---|
| [`ct-scalar`] | Scalar-field trait and shared constant-time scalar logic |
| [`subtle`] | Constant-time equality and `Choice` |
| [`zeroize`] | Secret zeroization |
| [`rand_core`] | `Rng` / `CryptoRng` traits only |

`ct-ts` is unconditionally `no_std` + `alloc` and has no system-RNG dependency
in its library graph; `rand` is a dev-dependency only. If you use
`getrandom`'s `SysRng`, note that it is fallible; wrap it in
`rand_core::UnwrapErr` to satisfy the infallible `Rng + CryptoRng` bounds.

## Documentation

- [`doc/design.md`](doc/design.md) — protocol and architecture design
- [`doc/implementation-notes.md`](doc/implementation-notes.md) — deviations
  from the design and their rationale

## License

Licensed under either of

- MIT License
- Apache License, Version 2.0

at your option.

[RFC 9591]: https://www.rfc-editor.org/rfc/rfc9591
[`Ciphersuite`]: src/ciphersuite.rs
[`PartyId`]: src/identifier.rs
[`ct-scalar`]: https://crates.io/crates/ct-scalar
[`subtle`]: https://crates.io/crates/subtle
[`zeroize`]: https://crates.io/crates/zeroize
[`rand_core`]: https://crates.io/crates/rand_core
