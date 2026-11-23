# `ct-ts` v0.0.1 — Design Document

## 1. Purpose & Scope

`ct-ts` is the threshold-signature layer of the `ct-*` family. Its first version implements **FROST (RFC 9591)** for **Ed25519**, with an architecture that accepts additional ciphersuites without reimplementing the protocol.

**In scope:** two-round DKG via Pedersen VSS, two-round threshold signing, Lagrange interpolation, constant-time secret handling.

**Out of scope (v0.0.1):** networking/serialization, preprocessing optimization, identifiable abort, non-Ed25519 ciphersuites, FIPS compliance.


## 2. Design Rationale

### 2.1 Why FROST

FROST is a **two-round threshold Schnorr protocol**. RFC 9591 specifies it generically over any prime-order group, and two ciphersuites are **Ed25519- and Ed448-compatible**: signatures they produce verify under any RFC 8032-compliant verifier.

The two-round structure is the minimal interactive pattern for threshold Schnorr without a trusted dealer:

- **Round 1 (Commit):** each signer publishes nonce commitments.
- **Round 2 (Sign):** each signer publishes a signature share; a coordinator aggregates.

FROST signatures are **not deterministic**. Deriving nonces deterministically would allow complete key recovery in the multi-party setting.

### 2.2 Why “core + ciphersuite” split

This mirrors `frost-core`, whose stated purpose is to “implement the base traits and types in a generic manner, to enable top-level implementations for different ciphersuites / curves without having to implement all of FROST from scratch”. End users are expected to depend on the curve-specific crate, not the core.

The seam is a single `Ciphersuite` trait, following the same shape as `frost-core`’s trait: associated types for the group and hash output, a `const ID: &'static str`, and `H1`–`H5` specialized to the subset Ed25519 needs:

```rust
pub trait Ciphersuite: Copy + Clone + PartialEq + Debug {
    type Scalar: ScalarField<LIMBS>;
    type Point: ProjectiveCurvePoint<LIMBS>;
    type Affine: AffineCurvePoint<LIMBS>;
    const LIMBS: usize;
    const ID: &'static str;

    fn H1(message: &[u8]) -> Self::Scalar;  // challenge
    fn H2(message: &[u8]) -> Self::Scalar;  // binding factor
    fn basepoint() -> Self::Point;
    fn mul_base(s: &Self::Scalar) -> Self::Point;
}
```

`ct-ts` contains **all protocol logic** and depends only on `ct-scalar` — not on `ct-ed25519` or `ct-curve-point`. `ct-ts-ed25519` is a thin wiring crate that implements `Ciphersuite` using `ct-ed25519`’s existing types.

### 2.3 Why two rounds are necessary

**Signing:** if all signers broadcast nonce values and signature shares in one round, the last broadcaster can choose its nonce after seeing everyone else’s. Round 1 locks commitments before any nonce value is revealed. The **binding factor** \(\rho_i = H_2(i, M, \{D_k, E_k\})\) binds each signer’s nonce to the full commitment set, preventing nonce-reuse attacks.

**DKG:** Round 1 distributes polynomial commitments and shares; Round 2 verifies shares against commitments and broadcasts a confirmation. Without Round 2, a dealer could distribute inconsistent shares and exit without an auditable record.

### 2.4 Why Lagrange is separated

Lagrange coefficients \(\lambda_i = \prod_{j \ne i} x_j / (x_j - x_i)\) operate on **public identifiers**. Scalar inversion on public data cannot leak secrets. Combining shares \(z = \sum \lambda_i z_i\), however, touches **secret shares** and must use constant-time `mul`/`add`. `ct-ts` enforces this boundary at the API level: `coefficients()` and `combine_shares()` are separate functions, with different secrecy assumptions.

### 2.5 Ed25519 `H2` compatibility

RFC 9591 states that FROST(Ed25519, SHA-512) **does not adhere** to the standard hash-to-curve requirement for `H2` alone, to maintain compatibility with Ed25519. `H2` is the **plain Ed25519 challenge hash** — no FROST domain prefix — so FROST(Ed25519) signatures verify under **any** standard Ed25519 verifier. The domain separator `FROST-ED25519-SHA512-v1` is mixed into `H1`, `H3`, `H4`, `H5` but **deliberately not into `H2`**.

`ct-ts-ed25519` must implement `H2` as bare SHA-512 reduced to a scalar via the Ed25519 challenge function — **not** generic hash-to-curve.

### 2.6 `no_std` + `alloc`, without a `std` feature

`ct-ts` needs `BTreeMap` and `Vec`, which live in `alloc`, not `core`. The standard pattern is `#![no_std]` plus `extern crate alloc` — this gives heap-backed types without pulling in the full standard library.

`ct-ts` goes one step further: **it has no `std` feature at all**. A `std` feature would be misleading, because `ct-ts` contains no code that needs `std` — only `alloc`. Adding `std` would create ambiguity about whether enabling it changes the crate’s behavior. It does not. The three lower layers (`ct-uint`, `ct-fp`, `ct-scalar`) are also pure `no_std` with no `std` feature; `ct-ts` stays consistent with them.

### 2.7 RNG policy: accept any `Rng`, do not forward a system RNG

`dkg_part1` and `sign_part1` take `R: rand_core::Rng + CryptoRng`. `ct-ts` does not care where the RNG comes from. `rand_core` is a regular dependency with `default-features = false`, providing only the traits.

**`OsRng` no longer exists in `rand_core` 0.10.** It has been removed together with the `os_rng` feature; the replacement is `getrandom::SysRng`, also exposed as `rand::rngs::SysRng`. `ct-ts` does **not** forward any system RNG. Examples and tests get `SysRng` through `rand 0.10.4`’s `sys_rng` feature in `[dev-dependencies]`; downstream users who want a system RNG add it themselves. This keeps the library’s dependency graph free of `getrandom` and avoids feature ambiguity.


## 3. Code Structure

```text
ct-ts/                          # Protocol core — no curve dependency, no std feature
├── Cargo.toml
└── src/
    ├── lib.rs                  # #![no_std], extern crate alloc
    ├── ciphersuite.rs          # Ciphersuite trait (the curve seam)
    ├── identifier.rs           # PartyId: NonZero newtype
    ├── error.rs                # Opaque Error newtype
    ├── lagrange.rs             # coefficients() + combine_shares()
    ├── keys.rs                 # KeyPackage, PublicKeyPackage
    ├── dkg/
    │   ├── mod.rs
    │   ├── round1.rs           # dkg_part1() -> (secret, package)
    │   └── round2.rs           # dkg_part2() -> (KeyPackage, PublicKeyPackage)
    └── sign/
        ├── mod.rs
        ├── round1.rs           # sign_part1() -> (nonces, commitment)
        └── round2.rs           # sign_part2() -> share; aggregate()

ct-ts-ed25519/                  # Ed25519 ciphersuite — thin wiring, no std feature
├── Cargo.toml
└── src/
    └── lib.rs                  # struct Ed25519Sha512; impl Ciphersuite
```


## 4. Module Design

### 4.1 `lib.rs`

```rust
#![no_std]
#![forbid(unsafe_code)]
extern crate alloc;
```

No `cfg(feature = "std")` anywhere. The crate is `no_std` + `alloc` unconditionally.

### 4.2 `ciphersuite.rs` — the only curve-facing interface

Every protocol module in `ct-ts` is generic over `C: Ciphersuite`; none imports `ct-ed25519`.

### 4.3 `identifier.rs` — `PartyId`

A `NonZero` newtype over `u16` (or `u32`). This is the \(x_i\) used in Lagrange interpolation and in binding factors. Always public.

### 4.4 `lagrange.rs` — split by secrecy

```rust
/// Public identifiers → coefficients. Non-constant-time is acceptable.
pub fn coefficients<C: Ciphersuite>(signers: &[PartyId]) -> Vec<C::Scalar>;

/// Secret shares × public coefficients → aggregate scalar.
/// MUST be constant-time.
pub fn combine_shares<C: Ciphersuite>(
    shares: &[C::Scalar],
    coeffs: &[C::Scalar],
) -> C::Scalar;
```

Mathematically, for a signing set \(S\):

\[
\lambda_i = \prod_{j \in S,\, j \ne i} \frac{x_j}{x_j - x_i} \pmod n
\]

`combine_shares` computes \(\sum_{i \in S} \lambda_i \cdot z_i\) using only `ScalarField::mul`/`add`.

### 4.5 `keys.rs` — key material

```rust
#[derive(ZeroizeOnDrop)]
pub struct KeyPackage<C: Ciphersuite> {
    pub identifier: PartyId,
    pub signing_share: C::Scalar,   // secret
    pub verifying_share: C::Point,  // public
}

pub struct PublicKeyPackage<C: Ciphersuite> {
    pub group_public_key: C::Point,
    pub verifying_shares: BTreeMap<PartyId, C::Point>,
}
```

`KeyPackage` is the **only** secret-bearing struct exposed after DKG; `ZeroizeOnDrop` wipes the share when the value leaves scope.

### 4.6 `dkg/` — Pedersen VSS DKG

```rust
// round1.rs
pub struct Round1Secret<C: Ciphersuite> { /* polynomial coefficients */ }
pub struct Round1Package<C: Ciphersuite> {
    pub commitment: Vec<C::Affine>,
    pub shares: BTreeMap<PartyId, C::Scalar>,
}

pub fn dkg_part1<C, R: rand_core::Rng + CryptoRng>(
    rng: &mut R,
    threshold: u16,
    participants: &[PartyId],
) -> (Round1Secret<C>, Round1Package<C>);
```

`dkg_part1` samples a degree-\(t\) polynomial \(f(x) = a_0 + a_1 x + \cdots + a_t x^t\), computes coefficient commitments \([a_j]G\), and evaluates shares \(f(x_i)\).

```rust
// round2.rs
pub fn dkg_part2<C: Ciphersuite>(
    secret: Round1Secret<C>,
    own_id: PartyId,
    round1_packages: &BTreeMap<PartyId, Round1Package<C>>,
) -> Result<(KeyPackage<C>, PublicKeyPackage<C>), Error>;
```

For each dealer \(j\), verify \([f_j(x_i)]G\) against \(j\)’s commitments; sum valid shares \(s_i = \sum_j f_j(x_i)\); construct the group public key \(Y = \sum_j [a_{j,0}]G\) as the sum of constant-term commitments.

### 4.7 `sign/` — two-round FROST signing

```rust
// round1.rs
#[derive(ZeroizeOnDrop)]
pub struct SigningNonces<C: Ciphersuite> { hiding: C::Scalar, binding: C::Scalar }
pub struct SignCommitment<C: Ciphersuite> { hiding: C::Affine, binding: C::Affine }

pub fn sign_part1<C, R: rand_core::Rng + CryptoRng>(
    rng: &mut R,
    key_package: &KeyPackage<C>,
) -> (SigningNonces<C>, SignCommitment<C>);
```

Nonces \((d_i, e_i)\) are **never sent**; only \(([d_i]G, [e_i]G)\) is broadcast. `SigningNonces` implements `ZeroizeOnDrop`.

```rust
// round2.rs
pub fn sign_part2<C: Ciphersuite>(
    nonces: SigningNonces<C>,
    key_package: &KeyPackage<C>,
    message: &[u8],
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
) -> Result<C::Scalar, Error>;

pub fn aggregate<C: Ciphersuite>(
    message: &[u8],
    public_key_package: &PublicKeyPackage<C>,
    commitments: &BTreeMap<PartyId, SignCommitment<C>>,
    shares: &BTreeMap<PartyId, C::Scalar>,
) -> Result<C::Signature, Error>;
```

`sign_part2` computes:

\[
\rho_i = H_2(i, M, \{D_k, E_k\}_{k \in S})
\]

\[
R = \sum_{k \in S} (D_k + \rho_k E_k)
\]

\[
c = H_1(Y, R, M)
\]

\[
z_i = d_i + \rho_i e_i + c \lambda_i s_i \pmod n
\]

`aggregate` computes \(z = \sum_{i \in S} z_i\) and returns the standard Ed25519 signature \((R, z)\) — verifiable by **any** Ed25519 verifier.

### 4.8 `error.rs`

Opaque `Error` newtype; no rich error variants that could leak protocol-internal state.


## 5. `ct-ts-ed25519` — wiring crate

```rust
use ct_ts::Ciphersuite;
use ct_ed25519::{Ed25519Scalar, Ed25519Point, Ed25519Affine, Ed25519Curve};
use sha2::{Digest, Sha512};

#[derive(Clone, Copy, PartialEq, Debug)]
pub struct Ed25519Sha512;

impl Ciphersuite for Ed25519Sha512 {
    type Scalar = Ed25519Scalar;
    type Point = Ed25519Point;
    type Affine = Ed25519Affine;
    const LIMBS: usize = 4;
    const ID: &'static str = "FROST-ED25519-SHA512-v1";

    fn H1(m: &[u8]) -> Self::Scalar { /* SHA-512 with FROST domain prefix */ }
    fn H2(m: &[u8]) -> Self::Scalar { /* bare Ed25519 challenge hash, NOT hash-to-curve */ }
    fn basepoint() -> Self::Point { Ed25519Point::basepoint() }
    fn mul_base(s: &Self::Scalar) -> Self::Point { Ed25519Curve::mul_base(s) }
}
```

`ct-ed25519` must make `Ed25519Scalar`, `Ed25519Point`, `Ed25519Affine`, and `Ed25519Curve` `pub`. This is a visibility change, not a logic change.


## 6. Dependencies

### 6.1 `ct-ts/Cargo.toml`

```toml
[package]
name = "ct-ts"
version = "0.0.1"
edition = "2021"
rust-version = "1.88"

[dependencies]
ct-scalar = { version = "0.0.2", default-features = false }
subtle = { version = "2.6.1", default-features = false }
zeroize = { version = "1.9.1", features = ["derive"], default-features = false }
rand_core = { version = "0.10.1", default-features = false }

[dev-dependencies]
hex = "0.4.3"
rand = { version = "0.10.4", features = ["std", "std_rng", "sys_rng"] }
```

**No `[features]` section.** `ct-ts` is unconditionally `no_std` + `alloc`. `rand_core` appears **only** in `[dependencies]`, providing `Rng` / `CryptoRng` traits; it is **not** duplicated in `[dev-dependencies]` because `OsRng` no longer exists in `rand_core` 0.10 — the system RNG comes from `rand::rngs::SysRng` via `rand`’s `sys_rng` feature.

**`rand_core` 0.10.1 breaking changes relevant to this design:**

- `RngCore` → `Rng`, `TryRngCore` → `TryRng`; the relationship becomes `Rng: TryRng<Error = Infallible>`.
- `OsRng` and the `os_rng` feature are **removed**; `rand_core::OsRng` is replaced by `getrandom::SysRng`.
- `rand` 0.10 renames the feature `os_rng` → `sys_rng` and the type `OsRng` → `SysRng`.

### 6.2 `ct-ts-ed25519/Cargo.toml`

```toml
[package]
name = "ct-ts-ed25519"
version = "0.0.1"
edition = "2021"
rust-version = "1.88"

[dependencies]
ct-ts = { version = "0.0.1", path = "../ct-ts", default-features = false }
ct-ed25519 = { version = "0.0.1", path = "../ct-ed25519", default-features = false }
sha2 = { version = "0.11.1", default-features = false }
subtle = { version = "2.6.1", default-features = false }

[dev-dependencies]
ct-ed25519 = { version = "0.0.1", path = "../ct-ed25519" }
hex = "0.4.3"
rand = { version = "0.10.4", features = ["std"] }
```

**No `[features]` section** here either.

### 6.3 What is not included

| Missing dependency | Reason |
|---|---|
| `curve25519-dalek` | `ct-ts-ed25519` uses `ct-ed25519`’s types; no direct dalek dependency. |
| `frost-core` / `frost-ed25519` | `ct-ts` implements FROST independently on its own `ct-*` arithmetic stack. It does not wrap `frost-core`. |
| `getrandom` | Not a regular dependency; `SysRng` is obtained through `rand`’s `sys_rng` feature in dev-dependencies only. |
| `serde` | v0.0.1 deliberately omits serialization. |
| `thiserror` / `anyhow` | Opaque `Error` newtype follows the `signature` crate’s design philosophy. |


## 7. Security Invariants for v0.0.1

| Invariant | Enforcement |
|---|---|
| Signing shares never serialized outside `KeyPackage` | `KeyPackage` is the only secret-bearing struct; `ZeroizeOnDrop` |
| Nonce values never broadcast | `SigningNonces` private fields; only commitments leave `sign_part1` |
| Nonce zeroization | `SigningNonces: ZeroizeOnDrop` |
| Share arithmetic constant-time | `combine_shares` and `sign_part2` use `ScalarField::mul`/`add` only |
| Lagrange inversion non-CT acceptable | `coefficients()` inputs are public `PartyId` |
| Ed25519 signature compatibility | `H2` is bare Ed25519 challenge hash, no FROST prefix |
| No secret-dependent branches | All secret comparisons use `subtle::Choice` |
| No `std` dependency | `#![no_std]` + `extern crate alloc`; no `std` feature exists |
| No system RNG in library dependency graph | `rand_core` only provides traits; `SysRng` is dev-only |


## 8. What v0.0.1 Deliberately Omits

- **Serialization / networking.** `ct-ts` returns `(secret, package)` pairs; the caller serializes and transports them.
- **Preprocessing.** FROST’s Round 1 can be precomputed asynchronously so signing becomes one round. Deferred to v0.0.2.
- **Identifiable abort.** `aggregate` returns an error if shares are invalid; per-share verification to identify misbehaving participants is RFC 9591’s optional robustness path, deferred.
- **Additional ciphersuites.** The `Ciphersuite` trait is the only extension point; `ct-ts-p256` etc. would be siblings of `ct-ts-ed25519`.


## 9. References

- RFC 9591 — FROST two-round Schnorr threshold signatures.
- `frost-core` — generic traits for different ciphersuites / curves.
- `frost-core::Ciphersuite` — associated types and `H1`/`H2` shape.
- FROST(Ed25519, SHA-512) `H2` compatibility: domain separator mixed into H1/H3/H4/H5 but **not** H2.
- `rand_core` 0.10 — `Rng` trait rename, `OsRng`/`os_rng` removal, `SysRng` replacement.
- `rand` 0.10 — `os_rng` → `sys_rng`, `OsRng` → `SysRng`.
