# ct-ed25519

A `no_std`, dependency-light implementation of the **Ed25519** signature scheme
(RFC 8032), written in Rust with constant-time arithmetic in mind.

The crate implements the full signature pipeline from scratch on top of the
[`ct-uint`], [`ct-fp`], [`ct-scalar`], and [`ct-curve-point`] building blocks:

- field arithmetic in $\mathbb{F}_p$
- scalar arithmetic modulo the group order $\ell$
- extended-coordinate Edwards point arithmetic
- point compression / decompression
- RFC 8032 key generation, signing, and verification

> **Status:** experimental. The implementation passes the RFC 8032 test
> vectors, but it has not been independently audited. Do not use it to protect
> production secrets without a security review.

## Features

- `#![no_std]`
- `#![forbid(unsafe_code)]`
- deterministic signatures (no RNG required)
- `zeroize` support for secret keys, enabled by default
- fixed-iteration scalar multiplication and limb-based field arithmetic
- RFC 8032 §7.1 test vectors included

## The Ed25519 curve

Ed25519 is the twisted Edwards curve

$$
E: -x^2 + y^2 = 1 + d x^2 y^2
$$

over the prime field $\mathbb{F}_p$, where

$$
p = 2^{255} - 19.
$$

The curve constant is

$$
d = -\frac{121665}{121666} \bmod p
  = \texttt{0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3}.
$$

The neutral element is $(0, 1)$, and the inverse of $P = (x, y)$ is
$-P = (-x, y)$.

The complete group law for $P_1 = (x_1, y_1)$ and $P_2 = (x_2, y_2)$ is

$$
x_3 = \frac{x_1 y_2 + x_2 y_1}{1 + d x_1 x_2 y_1 y_2},
\qquad
y_3 = \frac{y_1 y_2 + x_1 x_2}{1 - d x_1 x_2 y_1 y_2}.
$$

Because $a = -1$ is a square modulo $p$ and $d$ is a non-square, this addition
law is complete: the denominators are never zero for valid curve points.

### Group parameters

| Parameter | Value |
|---|---|
| Base field modulus | $p = 2^{255} - 19$ = `0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed` |
| Curve constant | $d = -121665/121666 \bmod p$ |
| Base point $x$ | `0x216936d3cd6e53fec0a4e231fdd6dc5c692cc7609525a7b2c9562d608f25d51a` |
| Base point $y$ | `0x6666666666666666666666666666666666666666666666666666666666666658` ($= 4/5 \bmod p$) |
| Base point order | $\ell$ = `0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed` |
| Cofactor | $h = 8$ |
| Full group order | $h\ell = 8\ell$ |

The order of the base point is the prime

$$
\ell = 2^{252} + 27742317777372353535851937790883648493.
$$

## Point representation

Affine points are stored as $(x, y)$. The implementation performs group
operations in **extended coordinates** $(X : Y : Z : T)$, which satisfy

$$
x = \frac{X}{Z}, \qquad y = \frac{Y}{Z}, \qquad T = \frac{XY}{Z},
$$

so that $XY = ZT$. The neutral element is $(0 : 1 : 1 : 0)$.

### Addition

For $P_1 = (X_1, Y_1, Z_1, T_1)$ and
$P_2 = (X_2, Y_2, Z_2, T_2)$, the implementation uses the unified
extended-coordinate formulas for $a = -1$:

$$
\begin{aligned}
A &= (Y_1 - X_1)(Y_2 - X_2), \\
B &= (Y_1 + X_1)(Y_2 + X_2), \\
C &= T_1 \cdot 2d \cdot T_2, \\
D &= 2 Z_1 Z_2, \\
E &= B - A, \\
F &= D - C, \\
G &= D + C, \\
H &= B + A,
\end{aligned}
\qquad
\begin{aligned}
X_3 &= EF, \\
Y_3 &= GH, \\
T_3 &= EH, \\
Z_3 &= FG.
\end{aligned}
$$

### Doubling

Doubling uses the dedicated formulas

$$
\begin{aligned}
A &= X_1^2, \\
B &= Y_1^2, \\
C &= 2 Z_1^2, \\
D &= -A, \\
E &= (X_1 + Y_1)^2 - A - B, \\
G &= D + B, \\
F &= G - C, \\
H &= D - B,
\end{aligned}
\qquad
\begin{aligned}
X_3 &= EF, \\
Y_3 &= GH, \\
T_3 &= EH, \\
Z_3 &= FG.
\end{aligned}
$$

## Field arithmetic

Field elements are represented as four 64-bit limbs modulo

$$
p = 2^{255} - 19.
$$

Multiplication first computes the full 512-bit product, then exploits

$$
2^{255} \equiv 19 \pmod p
\quad\Longrightarrow\quad
2^{256} \equiv 38 \pmod p
$$

to reduce the high half back into the low half. The result is conditionally
reduced modulo $p$.

## Encoding

### Compressed points (32 bytes)

A point $(x, y)$ is encoded as the little-endian encoding of $y$, with the
most significant bit set to the parity (sign) of $x$:

$$
\text{enc}(x, y) = \mathrm{LE}_{32}(y) \;\|\; (x \bmod 2) \ll 255.
$$

### Decompression

Given $y$ and the sign bit, decompression recovers $x$. Set

$$
u = y^2 - 1, \qquad v = d y^2 + 1.
$$

Then a square root is computed as

$$
x = u v^3 \left(u v^7\right)^{(p-5)/8} \pmod p.
$$

Afterwards:

- if $v x^2 = u$, the candidate is a square root;
- if $v x^2 = -u$, set $x \leftarrow x\sqrt{-1}$;
- otherwise the encoding is invalid.

The sign of $x$ is adjusted to match the encoded bit. The case $x = 0$ with
sign bit $1$ is rejected.

The constant $\sqrt{-1} \bmod p$ is

```text
0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0
```

### Uncompressed points (64 bytes)

Uncompressed points are the concatenation of the little-endian encodings of
$x$ and $y$:

$$
\text{enc}_{\text{uncompressed}}(x, y) = \mathrm{LE}_{32}(x) \;\|\; \mathrm{LE}_{32}(y).
$$

## Key generation

A private key is a 32-byte seed. Key generation follows RFC 8032:

$$
h = \text{SHA-512}(\text{seed}),
$$

split $h$ into two 32-byte halves:

$$
s = h[0..32], \qquad \text{prefix} = h[32..64].
$$

Clamp $s$:

```text
s[0]  &= 248
s[31] &= 127
s[31] |= 64
```

Interpret $s$ as a little-endian integer, reduce it modulo $\ell$ to obtain
the secret scalar $a$, and compute the public key

$$
A = [a]B.
$$

The public key is the 32-byte compressed encoding of $A$.

## Signing

Given a message $M$ and the values $(a, \text{prefix})$:

$$
\begin{aligned}
r &= \text{SHA-512}(\text{prefix} \;\|\; M) \bmod \ell, \\
R &= [r]B, \\
k &= \text{SHA-512}(\text{enc}(R) \;\|\; \text{enc}(A) \;\|\; M) \bmod \ell, \\
S &= (r + k a) \bmod \ell.
\end{aligned}
$$

The signature is

$$
\sigma = \text{enc}(R) \;\|\; \mathrm{LE}_{32}(S),
$$

which is exactly 64 bytes. Signing is deterministic: the same key and message
always produce the same signature.

## Verification

Given a message $M$, a public key $A$, and a signature $(R, S)$:

1. Decode $R$ as a compressed curve point.
2. Reject $S$ unless $S < \ell$ (canonical scalar encoding).
3. Compute
   $$
   k = \text{SHA-512}(\text{enc}(R) \;\|\; \text{enc}(A) \;\|\; M) \bmod \ell.
   $$
4. Accept exactly when
   $$
   [S]B = R + [k]A.
   $$

This is the cofactorless form of the RFC 8032 verification equation. RFC 8032
permits this form as a sufficient alternative to the cofactored equation
$[8][S]B = [8]R + [8][k]A$.

## Constant-time considerations

The crate is written with constant-time execution as a goal:

- field and scalar operations use fixed-size limb arithmetic;
- scalar multiplication uses a fixed 256-bit double-and-add loop with
  constant-time conditional selection;
- secret scalars are reduced with fixed-iteration code;
- points are compared with constant-time equality checks.

These properties are design goals, not a formal guarantee: the Rust compiler
is not required to preserve constant-time behaviour across all targets, and the
implementation has not been verified at the assembly level. The SHA-512
implementation is provided by the [`sha2`] crate.

When the default `zeroize` feature is enabled, `SigningKey` zeroizes its seed,
scalar, and prefix on drop.

## Building from this checkout

`Cargo.toml` currently contains a `[patch.crates-io]` entry that points at the
sibling `../ct-uint` checkout. This is needed because the crate uses the public
`Uint::from_limbs` and `Uint::limbs` constructors added to that checkout. Build
from a directory layout that contains both `ct-uint/` and `ct-ed25519/`, or
replace the patch with a published `ct-uint` release that exposes those
constructors.

## Usage

```toml
[dependencies]
ct-ed25519 = "0.0.1"
```

```rust
use ct_ed25519::{Signer, SigningKey, Verifier, VerifyingKey};

// A 32-byte private seed.
let seed = [0x42u8; 32];
let signing_key = SigningKey::from_bytes(&seed);

// The public key is derived from the seed.
let public_key_bytes = signing_key.verifying_key().to_bytes();
let verifying_key = VerifyingKey::from_bytes(&public_key_bytes).unwrap();

let message = b"example message";
let signature = signing_key.sign(message);

verifying_key.verify(message, &signature).unwrap();
```

Malformed or tampered signatures return a `signature::Error` from `verify`.
`Signature` can also be constructed from a 64-byte slice with
`Signature::try_from(&bytes[..])`.

### Low-level curve and scalar types

The curve and scalar types are public so they can be used by related crates
(for example, threshold-signature implementations):

```rust
use ct_ed25519::{Ed25519Affine, Ed25519Curve, Ed25519Point, Ed25519Scalar};
use ct_ed25519::{PointEncoding, ProjectiveCurvePoint, ScalarField, ScalarMul};

let basepoint: Ed25519Point = Ed25519Point::basepoint();
let affine: Ed25519Affine = basepoint.to_affine();

let scalar = Ed25519Scalar::from_bytes_mod_order(&[7u8; 32]);
let product = Ed25519Curve::mul_base(&scalar);

let mut encoded = [0u8; 32];
product.to_affine().to_compressed(&mut encoded);
```

The traits needed to operate on these types (`PointEncoding`,
`ProjectiveCurvePoint`, `ScalarMul`, `ScalarField`, and the other traits from
the `ct-*` crates) are re-exported from `ct_ed25519`.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `zeroize` | yes | Zeroize `SigningKey` secrets on drop and enable `ct-uint`'s zeroization support. |

With `default-features = false`, the crate builds without `zeroize` support.

## Tests

The test suite includes the RFC 8032 §7.1 vectors (including the empty
message, one- and two-byte messages, and `SHA(abc)`), plus tampering checks:

```sh
cargo test
cargo test --no-default-features
```

## Security notes

- This crate has **not been audited**. Treat it as experimental.
- Verification uses the cofactorless equation. It does not reject small-order
  public keys or enforce prime-order subgroup membership on decoded points.
  Protocols that require strict key validation (for example, some consensus
  and interoperability profiles) should add those checks at a higher layer.
- Signature verification only requires that $R$ decodes and that $S < \ell$.
  It does not implement every optional strictness rule used by other Ed25519
  implementations.
- Ed25519 is intended for single-key signatures, not for general-purpose
  elliptic-curve key exchange or encryption.
- The implementation prioritizes clarity and constant-time structure over
  speed. `mul_base` currently uses the generic scalar multiplication path;
  precomputed base-point tables are a future optimization.

## License

Licensed under either of

- MIT License
- Apache License, Version 2.0

at your option.

[`ct-uint`]: https://crates.io/crates/ct-uint
[`ct-fp`]: https://crates.io/crates/ct-fp
[`ct-scalar`]: https://crates.io/crates/ct-scalar
[`ct-curve-point`]: https://crates.io/crates/ct-curve-point
[`sha2`]: https://crates.io/crates/sha2
