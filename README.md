# security

A `no_std` Rust workspace for constant-time elliptic-curve cryptography. It
provides fixed-width integer and field primitives, Ed25519 signatures
(RFC 8032), and the FROST threshold Schnorr protocol (RFC 9591).

> **Status:** experimental. The crates pass their test suites, including
> RFC 8032 vectors and end-to-end FROST roundtrips, but none has been
> independently audited. Do not use them to protect production secrets
> without a security review.

## Crates

The workspace is layered from arithmetic primitives up to signatures:

| Crate | Role |
|---|---|
| [`ct-uint`](crates/ct-uint) | Constant-time fixed-width big integers and limb arithmetic |
| [`ct-fp`](crates/ct-fp) | Prime-field arithmetic trait and shared logic |
| [`ct-scalar`](crates/ct-scalar) | Scalar-field trait and shared logic |
| [`ct-curve-point`](crates/ct-curve-point) | Elliptic-curve point abstraction traits |
| [`ct-ed25519`](crates/ct-ed25519) | Constant-time Ed25519 signatures (RFC 8032) |
| [`ct-ts`](crates/ct-ts) | FROST threshold Schnorr protocol core (RFC 9591) |
| [`ct-ts-ed25519`](crates/ct-ts-ed25519) | FROST(Ed25519, SHA-512) ciphersuite for `ct-ts` |

Dependency flow:

```text
ct-uint ──► ct-fp ──► ct-scalar ──► ct-curve-point ──► ct-ed25519 ──► ct-ts-ed25519
             │           │                                   ▲              ▲
             └───────────┴───────────────────────────────────┘              │
                                                             ct-ts ─────────┘
```

All crates are `#![no_std]` and `#![forbid(unsafe_code)]`. Zeroization of
secret material is available where applicable: `ct-uint` and `ct-ed25519`
expose a `zeroize` feature, and `ct-ts` zeroizes unconditionally.

## Layout

```text
.
├── Cargo.toml              # workspace package metadata, dependencies, lints
├── rust-toolchain.toml     # pinned Rust toolchain
├── crates/
│   ├── ct-uint/
│   ├── ct-fp/
│   ├── ct-scalar/
│   ├── ct-curve-point/
│   ├── ct-ed25519/
│   ├── ct-ts/
│   │   └── doc/            # protocol design and implementation notes
│   └── ct-ts-ed25519/
└── docs/
```

## Requirements

- Rust 1.100.0 (installed automatically by `rustup` from `rust-toolchain.toml`)
- Edition 2024; workspace MSRV is 1.98
- `rustfmt` and `clippy` components

## Build and test

```bash
cargo build --workspace
cargo test --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets
```

Feature-matrix checks for the crates with optional zeroization:

```bash
cargo test -p ct-uint --no-default-features
cargo test -p ct-ed25519 --no-default-features
cargo test -p ct-ed25519 --features zeroize
```

## Security

These crates are research-grade and unaudited. Constant-time behavior is a
design goal, not a guarantee: scalar multiplication, field arithmetic, and
secret-dependent branches have not been formally verified. Treat any
production use as requiring an independent cryptographic and side-channel
review.

## License

Licensed under either of:

- Apache License, Version 2.0
- MIT License

at your option.
