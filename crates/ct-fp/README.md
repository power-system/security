# ct-fp

A `no_std` trait for prime-field arithmetic over fixed-width integers, with
constant-time default operations. It is the field layer between `ct-uint` and
the scalar/curve crates.

> **Status:** experimental and unaudited. A concrete field is only as
> constant-time as its required `mul` implementation.

## Design

### Field model

`PrimeField<const LIMBS: usize>` represents an element of
$\mathbb{F}_p$ as a `Uint<LIMBS>` in the range $[0, p)$, where

$$
p = \texttt{PrimeField::MODULUS}.
$$

The trait requires `Copy + ConstantTimeEq + ConditionallySelectable` and asks
the implementer for four items:

- `MODULUS`
- `mul`
- `from_uint`
- `to_uint`

Every other operation has a default implementation.

### Modules

| Module | Responsibility |
|---|---|
| `prime_field` | The `PrimeField` trait and its default operations |
| `helpers` | `conditional_sub_p`, a constant-time conditional subtraction |
| `pow` | Constant-time square-and-multiply exponentiation |

### Default operations

Addition is a wrapping limb addition followed by a conditional subtraction of
$p$:

$$
a \oplus b =
\begin{cases}
a + b - p, & a + b \ge p,\\
a + b, & a + b < p.
\end{cases}
$$

Subtraction adds $p$ back when the difference underflows:

$$
a \ominus b =
\begin{cases}
a - b + p, & a < b,\\
a - b, & a \ge b.
\end{cases}
$$

Negation is $0 \ominus a$. Squaring is `mul(a, a)`. Inversion uses Fermat's
little theorem:

$$
a^{-1} \equiv a^{p-2} \pmod p,
$$

which requires $p$ to be prime and is limited to fields of at most 8 limbs
(512 bits).

Exponentiation treats the exponent as little-endian bytes and uses a
left-to-right binary ladder, selecting the multiplied value with
`subtle::Choice`:

$$
a^e = \prod_{j:\,e_j=1} a^{2^j}.
$$

## Usage

### Using an existing field

`ct-ed25519` exposes `Ed25519Scalar`, a concrete `PrimeField<4>`
implementation:

```rust
use ct_ed25519::{Ed25519Scalar, PrimeField, ScalarField};
use subtle::ConstantTimeEq;

let a = Ed25519Scalar::from_bytes_mod_order(&[7u8; 32]);
let inverse = a.invert();

assert!(bool::from(a.mul(&inverse).ct_eq(&Ed25519Scalar::one())));
```

Within the workspace, use a path dependency:

```toml
[dependencies]
ct-fp = { path = "../ct-fp" }
```

### Implementing the trait

A concrete field supplies its modulus and a constant-time `mul`. The
following single-limb toy field is for illustration only; the `%` operator is
not constant-time and must not be used in production code.

```rust
use ct_fp::PrimeField;
use ct_uint::Uint;
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

#[derive(Clone, Copy)]
struct Toy(u64);

impl ConstantTimeEq for Toy {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Toy {
    fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
        Self(u64::conditional_select(&a.0, &b.0, choice))
    }
}

const P: u64 = 0xFFFF_FFFF_FFFF_FFC5; // 2^64 - 59

impl PrimeField<1> for Toy {
    const MODULUS: Uint<1> = Uint::from_u64(P);

    fn mul(&self, rhs: &Self) -> Self {
        Self(((self.0 as u128 * rhs.0 as u128) % P as u128) as u64)
    }

    fn from_uint(v: Uint<1>) -> Self {
        Self(v.to_u64().unwrap())
    }

    fn to_uint(&self) -> Uint<1> {
        Uint::from_u64(self.0)
    }
}
```

For a field with $N$ limbs, the modulus must fit in $N$ limbs and every
`from_uint` input must already be reduced. `mul` must return a canonical
element in $[0, p)$.

## API reference

### `PrimeField<LIMBS>`

| Item | Kind | Description |
|---|---|---|
| `MODULUS` | required const | Field modulus as `Uint<LIMBS>` |
| `mul(&self, &Self) -> Self` | required | Constant-time field multiplication |
| `from_uint(Uint<LIMBS>) -> Self` | required | Interpret an integer as a field element |
| `to_uint(&self) -> Uint<LIMBS>` | required | Canonical integer representation |
| `zero()` | provided | Additive identity |
| `one()` | provided | Multiplicative identity |
| `add(&self, &Self) -> Self` | provided | Addition modulo $p$ |
| `sub(&self, &Self) -> Self` | provided | Subtraction modulo $p$ |
| `neg(&self) -> Self` | provided | Additive inverse |
| `square(&self) -> Self` | provided | `mul(self, self)` |
| `pow(&self, exponent_le_bytes) -> Self` | provided | Exponentiation by little-endian bytes |
| `invert(&self) -> Self` | provided | $a^{p-2}$; panics above 8 limbs |
| `ct_is_zero(&self) -> Choice` | provided | Constant-time zero test |

### Helpers

| Item | Description |
|---|---|
| `helpers::conditional_sub_p(v, p)` | Return $v-p$ when $v \ge p$, otherwise $v$ |
| `pow::pow(base, exponent_le_bytes)` | Constant-time exponentiation used by `PrimeField::pow` |

## Feature flags

`ct-fp` defines no features of its own. It depends on `ct-uint` with default
features disabled.

## Tests

`tests/toy_field.rs` exercises add/sub/neg, multiplication and squaring,
Fermat inversion, and exponentiation against a naive reference.

```sh
cargo test -p ct-fp
```

## Security notes

- The default operations assume canonical inputs in $[0, p)$.
- `invert` relies on $p$ being prime; the trait cannot enforce that.
- The default addition performs one conditional subtraction. Moduli and
  operand ranges must be chosen so the sum does not wrap the limb
  representation.
- Constant-time behaviour depends on the implementer's `mul`; a variable-time
  multiplication undermines the whole field.

## License

Licensed under either of MIT or Apache-2.0, at your option.
