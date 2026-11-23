# ct-curve-point

Curve-agnostic traits for elliptic-curve points, encodings, and scalar
multiplication. The crate contains no concrete curve; it defines the seam
that a curve implementation (for example `ct-ed25519`) fills in.

> **Status:** experimental and unaudited. Constant-time guarantees come from
> the concrete curve implementation, not from these traits.

## Design

### Group model

A curve point type represents an element of a prime-order group $G$ with
identity $\mathcal{O}$. The `CurvePoint` trait exposes the group operations

$$
P + Q, \qquad 2P, \qquad -P, \qquad P = \mathcal{O}?
$$

and requires constant-time equality (`ConstantTimeEq`) and selection
(`ConditionallySelectable`).

Scalar multiplication is separated into its own trait:

$$
[k]P = \underbrace{P + \cdots + P}_{k\ \text{times}},
\qquad [k]G = \texttt{mul\_base}(k),
$$

where $G$ is the group generator and $k$ is a scalar in $\mathbb{F}_n$.

### Trait hierarchy

```text
CurvePoint
├── ProjectiveCurvePoint<LIMBS>  → to_affine()
└── AffineCurvePoint<LIMBS>      → coordinate bytes for encoding

CurveModel<LIMBS>
├── Scalar: ScalarField<LIMBS>
├── ProjectivePoint: ProjectiveCurvePoint<LIMBS>
├── AffinePoint: AffineCurvePoint<LIMBS>
└── identity()

ScalarMul<LIMBS>: CurveModel<LIMBS>
├── mul(point, scalar)
└── mul_base(scalar)

PointEncoding
├── COMPRESSED_LEN / UNCOMPRESSED_LEN
└── from_* / to_* / ct_is_valid
```

`ProjectiveCurvePoint` and `AffineCurvePoint` are separate because secret
arithmetic typically uses a projective representation while public
commitments and wire formats use affine coordinates. `CurveModel` ties both
point types to the scalar field of order $n$.

### Modules

| Module | Responsibility |
|---|---|
| `curve_model` | `CurvePoint`, `ProjectiveCurvePoint`, `AffineCurvePoint`, `CurveModel` |
| `encoding` | `PointEncoding`: lengths, encode/decode, validity |
| `scalar_mul` | `ScalarMul`: arbitrary-point and base-point multiplication |

## Usage

### Using the Ed25519 implementation

`ct-ed25519` supplies a concrete curve model:

```rust
use ct_ed25519::{
    CurvePoint, Ed25519Affine, Ed25519Curve, Ed25519Point, Ed25519Scalar,
    PointEncoding, ProjectiveCurvePoint, ScalarField, ScalarMul,
};

let generator = Ed25519Point::basepoint();
let scalar = Ed25519Scalar::from_bytes_mod_order(&[2u8; 32]);
let point = Ed25519Curve::mul_base(&scalar);

let affine: Ed25519Affine = point.to_affine();
let mut compressed = [0u8; 32];
affine.to_compressed(&mut compressed);

assert!(bool::from(affine.ct_is_valid()));
```

Within the workspace, use the path dependency:

```toml
[dependencies]
ct-curve-point = { path = "../ct-curve-point" }
```

### Implementing a new curve

A complete curve implementation provides:

1. `PrimeField<LIMBS>` and `ScalarField<LIMBS>` for its scalar type.
2. `CurvePoint` for the projective and affine point types.
3. `ProjectiveCurvePoint<LIMBS>` and `AffineCurvePoint<LIMBS>`.
4. `PointEncoding` for the affine type.
5. `CurveModel<LIMBS>` wiring the scalar, projective, and affine types.
6. `ScalarMul<LIMBS>` with constant-time multiplication.

The result can then be used by protocol crates (such as `ct-ts`) through their
ciphersuite traits.

## API reference

### `CurvePoint`

| Item | Description |
|---|---|
| `add(&self, &Self) -> Self` | Group addition |
| `double(&self) -> Self` | Point doubling |
| `neg(&self) -> Self` | Group inverse |
| `ct_is_identity(&self) -> Choice` | Constant-time identity test |

Required supertraits: `Copy + Clone + ConstantTimeEq + ConditionallySelectable
+ Sized`.

### `ProjectiveCurvePoint<LIMBS>`

| Item | Description |
|---|---|
| `type Curve: CurveModel<LIMBS>` | Owning curve model |
| `to_affine(&self) -> Curve::AffinePoint` | Convert to affine coordinates |

### `AffineCurvePoint<LIMBS>`

| Item | Description |
|---|---|
| `type Curve: CurveModel<LIMBS>` | Owning curve model |
| `affine_x_bytes(&self) -> &[u8]` | Encoded $x$ coordinate |
| `affine_y_bytes(&self) -> &[u8]` | Encoded $y$ coordinate |

### `CurveModel<LIMBS>`

| Item | Description |
|---|---|
| `type Scalar: ScalarField<LIMBS>` | Scalar field of the group order |
| `type ProjectivePoint: ProjectiveCurvePoint<LIMBS>` | Projective point |
| `type AffinePoint: AffineCurvePoint<LIMBS>` | Affine point |
| `identity() -> Self::ProjectivePoint` | Group identity |

### `PointEncoding`

| Item | Description |
|---|---|
| `COMPRESSED_LEN` | Compressed encoding length in bytes |
| `UNCOMPRESSED_LEN` | Uncompressed encoding length in bytes |
| `from_compressed(bytes) -> Option<Self>` | Decode compressed form |
| `from_uncompressed(bytes) -> Option<Self>` | Decode uncompressed form |
| `to_compressed(&self, out)` | Encode compressed form |
| `to_uncompressed(&self, out)` | Encode uncompressed form |
| `ct_is_valid(&self) -> Choice` | Constant-time validity check |

### `ScalarMul<LIMBS>`

| Item | Description |
|---|---|
| `mul(point, scalar) -> Point` | Constant-time $[k]P$ |
| `mul_base(scalar) -> Point` | Constant-time $[k]G$ |

## Tests

`tests/toy_curve.rs` implements a toy scalar field, projective/affine point
types, a curve model, encoding, and scalar multiplication, then instantiates
every trait.

```sh
cargo test -p ct-curve-point
```

## Security notes

- These are abstractions; they cannot enforce constant-time arithmetic.
- Decoding must reject invalid encodings and, where the protocol requires it,
  points outside the prime-order subgroup.
- `mul_base` may share the generic multiplication path unless the curve
  implementation supplies a constant-time precomputed table.

## License

Licensed under either of MIT or Apache-2.0, at your option.
