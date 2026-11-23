# ct-scalar

A `no_std` scalar-field trait for constant-time cryptography. `ScalarField`
extends [`ct-fp`]'s `PrimeField` with scalar-specific validation and byte
reduction helpers.

> **Status:** experimental and unaudited. The default helpers are
> constant-time only if the underlying field multiplication is.

## Design

### Scalar field model

A scalar field is the prime field $\mathbb{F}_n$ of the group order. The
modulus is inherited from `PrimeField::MODULUS`; `ScalarField` adds:

- a validity predicate for canonical non-zero scalars, and
- conversion from byte strings with reduction modulo $n$.

A scalar $s$ is valid when

$$
0 < s < n.
$$

The zero check and the comparison with $n$ are both constant-time
(`Choice`), never early-exit `bool` comparisons.

### Byte reduction

The default `from_bytes_mod_order` treats its input as a **big-endian**
integer. It applies Horner's rule:

$$
s = \bigl(\cdots((b_0 \cdot 256 + b_1) \cdot 256 + b_2)\cdots\bigr) \bmod n.
$$

`from_bytes_wide` requires exactly $2N$ bytes, where $N$ is the number of
64-bit limbs, and applies the same reduction. A concrete scalar type may
override these methods when its wire format uses another byte order; for
example, Ed25519 scalars are little-endian and override both.

### Module layout

| Module | Responsibility |
|---|---|
| `scalar_field` | The `ScalarField` trait and its default helpers |

## Usage

Use a concrete scalar type such as `ct-ed25519::Ed25519Scalar`:

```rust
use ct_ed25519::{Ed25519Scalar, ScalarField};

let small = Ed25519Scalar::from_bytes_mod_order(&[1u8; 32]);
assert!(bool::from(small.is_valid_scalar()));

let wide = Ed25519Scalar::from_bytes_wide(&[0xFFu8; 64]);
assert!(bool::from(wide.is_valid_scalar()));
```

Within the workspace, depend on the crate by path:

```toml
[dependencies]
ct-scalar = { path = "../ct-scalar" }
```

To define a new scalar field, first implement `ct_fp::PrimeField<LIMBS>` for
your type, then write:

```rust
impl ct_scalar::ScalarField<4> for MyScalar {}
```

The default methods are then available. Override `from_bytes_mod_order` and
`from_bytes_wide` if your encoding is not big-endian.

## API reference

### `ScalarField<LIMBS>`

`ScalarField` is a subtrait of `PrimeField<LIMBS>`, so every field operation
(`add`, `sub`, `neg`, `mul`, `square`, `pow`, `invert`, `ct_is_zero`, and the
`zero`/`one` constructors) is also available.

| Item | Description |
|---|---|
| `is_valid_scalar(&self) -> Choice` | Constant-time test for $0 < s < n$ |
| `from_bytes_mod_order(bytes) -> Self` | Reduce a big-endian integer modulo $n$; overridable |
| `from_bytes_wide(bytes) -> Self` | Reduce exactly $2N$ big-endian bytes modulo $n$; overridable |

## Tests

`tests/toy_scalar.rs` checks the validity range, big-endian reduction
(including overflow), wide reduction, and the required wide-input length.

```sh
cargo test -p ct-scalar
```

## Security notes

- `is_valid_scalar` rejects zero and values $\ge n$; it does not check that
  the input was canonical on the wire.
- A malformed or non-canonical scalar must not be accepted as a secret
  signing share without a separate protocol-level validation.
- The default byte reduction is only as constant-time as the field's `mul`.

## License

Licensed under either of MIT or Apache-2.0, at your option.
