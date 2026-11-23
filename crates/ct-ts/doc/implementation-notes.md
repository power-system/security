# Implementation notes for `ct-ts` v0.0.1

`doc/design.md` is the design source. This file records the places where the
implementation had to resolve contradictions or fill gaps in that document.

## RFC 9591 hash roles

`doc/design.md` labels `H1` as the challenge and `H2` as the binding factor,
but RFC 9591 defines them the other way around:

| Function | RFC 9591 role |
|---|---|
| `H1` | Binding factor `rho` with `"rho"` domain separator |
| `H2` | Bare Ed25519 challenge hash (no FROST prefix) |
| `H3` | Nonce derivation with `"nonce"` domain separator |
| `H4` | Message prehash with `"msg"` domain separator |
| `H5` | Commitment-list prehash with `"com"` domain separator |

The implementation follows the RFC. Using a FROST-prefixed `H1` as the
challenge, as the design's formula literally says, would produce signatures
that fail standard Ed25519 verification.

## Method-based `Ciphersuite` seam

The design's `Ciphersuite` snippet bounds `Scalar`, `Point`, and `Affine` with
`ct_scalar::ScalarField` and `ct_curve_point` traits, while the same document
states that `ct-ts` must not depend on `ct-curve-point`. Stable Rust also
cannot use the associated `LIMBS` constant as the const argument to
`ScalarField<LIMBS>`.

The implementation keeps a single `Ciphersuite` trait but routes every group
and scalar operation through methods on that trait. `ct-ts` therefore adds no
curve dependency and still keeps the protocol independent of a concrete
group.

## `KeyPackage` carries the group public key

The design's `sign_part2(key_package, message, commitments)` signature has no
way to obtain the group public key, but RFC 9591 binding factors and the
challenge both require it. `KeyPackage` therefore includes a public
`group_public_key` field.

## `dkg_part1` returns `Result`

`doc/design.md` shows an infallible `dkg_part1`. The implementation returns
`Result` so that a zero threshold, a threshold larger than the participant
set, or duplicate participant identifiers are rejected instead of panicking.

`threshold` is the minimum number of signers. The sampled polynomial has
degree `threshold - 1`, matching the RFC 9591 convention.

## Tests

`tests/toy_protocol.rs` implements a deliberately insecure toy ciphersuite over
the additive group modulo `2^61 - 1`. It exercises DKG, share verification,
threshold signing, aggregation, Lagrange interpolation, and the standard
Schnorr verification equation without adding a real curve dependency to the
core crate.
