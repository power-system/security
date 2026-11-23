# ct-uint

Fixed-width unsigned integers and limb arithmetic for constant-time
cryptography. The crate is `#![no_std]` and `#![forbid(unsafe_code)]`.

> **Status:** experimental and unaudited. The operations avoid
> secret-dependent branches, but constant-time behaviour is not formally
> verified across every compiler and target.

## Design

### Representation

A `Uint<LIMBS>` is an array of `LIMBS` 64-bit `Limb` values in
little-endian limb order:

$$
x = \sum_{i=0}^{N-1} x_i \, 2^{64i},
\qquad 0 \le x_i < 2^{64}.
$$

`Uint::limbs()[0]` is the least significant limb. `Limb` is a newtype over
`u64` with the carry/borrow primitives needed by multi-limb arithmetic.

### Modules

| Module | Responsibility |
|---|---|
| `limb` | `Limb`, `adc`, `sbb`, `mac` |
| `uint` | `Uint<LIMBS>` construction, add/sub, widening multiply |
| `ct` | Constant-time comparisons, selection, and negation |
| `encoding` | Little- and big-endian byte conversion |

### Constant-time strategy

Carry and borrow values are kept in `Limb`s, and comparisons return
`subtle::Choice` rather than `bool`. `Uint` implements `ConstantTimeEq` and
`ConditionallySelectable`, so secret-dependent choices can be made with
`conditional_select` without a branch.

## Arithmetic

### Addition and subtraction

For each limb, addition computes

$$
a_i + b_i + c_i = r_i + 2^{64} c_{i+1},
$$

where $c_i$ is the incoming carry. Subtraction computes

$$
a_i - b_i - b_i^{\mathrm{in}} \equiv r_i \pmod{2^{64}},
$$

and returns the outgoing borrow $b_{i+1}$.

`checked_add` and `checked_sub` return `(result, Choice)`, where the
`Choice` is the final carry or borrow. `wrapping_*` discards it.

### Multiplication

`widening_mul` multiplies two $N$-limb values and returns the full
$2N$-limb product split into low and high halves:

$$
x y = \mathrm{lo} + 2^{64N}\,\mathrm{hi}.
$$

Each partial product is accumulated in 128-bit arithmetic:

$$
a_i b_j + \mathrm{acc} + \mathrm{carry}
= r + 2^{64}\,\mathrm{carry}'.
$$

## Usage

```toml
[dependencies]
ct-uint = "0.1.5"
```

Within this workspace, depend on it by path instead:

```toml
[dependencies]
ct-uint = { path = "../ct-uint" }
```

```rust
use ct_uint::{Limb, Uint};

type U256 = Uint<4>;

let a = U256::from_u64(6);
let b = U256::from_u64(7);

let (sum, carry) = a.checked_add(&b);
assert!(!bool::from(carry));
assert_eq!(sum.to_u64(), Some(13));

let (lo, hi) = a.widening_mul(&b);
assert_eq!(lo.to_u64(), Some(42));
assert_eq!(hi.to_u64(), Some(0));

let (r, c) = Limb::from_u64(u64::MAX).adc(Limb::ONE, Limb::ZERO);
assert_eq!(r.to_u64(), 0);
assert_eq!(c.to_u64(), 1);
```

## API reference

### `Limb`

| Item | Description |
|---|---|
| `ZERO`, `ONE`, `MAX` | Constant limb values |
| `from_u64`, `to_u64` | Convert to and from `u64` |
| `adc(rhs, carry)` | Add with carry; returns `(sum, carry_out)` |
| `sbb(rhs, borrow)` | Subtract with borrow; returns `(difference, borrow_out)` |
| `mac(rhs, carry)` | Multiply-accumulate; returns `(low, high)` of a 128-bit result |

`Limb` also implements `ConstantTimeEq`, `ConditionallySelectable`, and,
with the `zeroize` feature, `Zeroize`.

### `Uint<LIMBS>`

| Item | Description |
|---|---|
| `ZERO`, `ONE` | Constant values |
| `from_u64`, `to_u64` | Construct from or narrow to `u64`; `to_u64` returns `None` if high limbs are non-zero |
| `from_limbs`, `limbs` | Build from or borrow the limb array |
| `checked_add`, `checked_sub` | Wrapping operation plus carry/borrow `Choice` |
| `wrapping_add`, `wrapping_sub` | Operation without the carry/borrow result |
| `widening_mul` | Full product as `(low, high)` halves |
| `from_le_bytes`, `from_be_bytes` | Decode exactly `LIMBS * 8` bytes; returns `None` on wrong length |
| `write_le_bytes`, `write_be_bytes` | Encode into exactly `LIMBS * 8` bytes |
| `ct_eq`, `ct_lt`, `ct_is_zero` | Constant-time comparisons returning `Choice` |
| `conditional_negate` | Negate modulo $2^{64N}$ when a `Choice` is set |

The type also implements `ConstantTimeEq`, `ConditionallySelectable`,
`Default` (zero), and, with the `zeroize` feature, `Zeroize`.

## Feature flags

| Feature | Default | Description |
|---|---|---|
| `zeroize` | yes | Implements `Zeroize` for `Limb` and `Uint` |

## Tests

`tests/smoke.rs` covers carry/borrow, add/sub roundtrips, small and full-limb
widening multiplication, and byte roundtrips.

```sh
cargo test -p ct-uint
cargo test -p ct-uint --no-default-features
```

## Security notes

- No cryptographic protocol is implemented here; this crate only provides
  arithmetic building blocks.
- The implementation targets constant-time behaviour, but the Rust compiler
  is not guaranteed to preserve it on every target.
- `widening_mul` returns the full product; reduction modulo a field or group
  order is the caller's responsibility.

## License

Licensed under either of MIT or Apache-2.0, at your option.
