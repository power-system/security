use ct_fp::{PrimeField, helpers::conditional_sub_p};
use ct_scalar::ScalarField;
use ct_uint::{Limb, Uint};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const L: Uint<4> = Uint::from_limbs([
    Limb::from_u64(0x5812_631A_5CF5_D3ED),
    Limb::from_u64(0x14DE_F9DE_A2F7_9CD6),
    Limb::from_u64(0x0000_0000_0000_0000),
    Limb::from_u64(0x1000_0000_0000_0000),
]);

#[derive(Clone, Copy, Debug)]
pub struct Ed25519Scalar(pub(crate) Uint<4>);

impl ConstantTimeEq for Ed25519Scalar {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Ed25519Scalar {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self(Uint::conditional_select(&a.0, &b.0, c))
    }
}

impl Ed25519Scalar {
    /// Decode a canonical little-endian scalar, rejecting values `>= L`.
    pub fn from_canonical_bytes(b: &[u8; 32]) -> Option<Self> {
        let v = Uint::<4>::from_le_bytes(b)?;
        let (_, underflow) = v.checked_sub(&L);
        if bool::from(underflow) {
            Some(Self(v))
        } else {
            None
        }
    }

    /// Encode the scalar as 32 little-endian bytes.
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.write_le_bytes(&mut out);
        out
    }
}

impl PrimeField<4> for Ed25519Scalar {
    const MODULUS: Uint<4> = L;

    /// 0.0.1: 512-iteration constant-time bit reduction.
    /// 0.0.2 MUST replace this with Montgomery reduction.
    fn mul(&self, rhs: &Self) -> Self {
        let (lo, hi) = self.0.widening_mul(&rhs.0);
        let mut acc = Uint::<4>::ZERO;
        for bit_idx in (0..512).rev() {
            let (doubled, ovf) = acc.checked_add(&acc);
            let (reduced, uf) = doubled.checked_sub(&L);
            acc = Uint::conditional_select(&doubled, &reduced, ovf | !uf);

            let limb_idx = bit_idx / 64;
            let bit_pos = bit_idx % 64;
            let limb = if limb_idx < 4 {
                lo.limbs()[limb_idx].to_u64()
            } else {
                hi.limbs()[limb_idx - 4].to_u64()
            };
            let bit = Choice::from(((limb >> bit_pos) & 1) as u8);

            let (plus, _) = acc.checked_add(&Uint::ONE);
            let (plus_r, uf2) = plus.checked_sub(&L);
            let plus_final = Uint::conditional_select(&plus, &plus_r, !uf2);
            acc = Uint::conditional_select(&acc, &plus_final, bit);
        }
        Self(acc)
    }

    fn from_uint(v: Uint<4>) -> Self {
        Self(conditional_sub_p(v, &L))
    }

    fn to_uint(&self) -> Uint<4> {
        self.0
    }
}

impl ScalarField<4> for Ed25519Scalar {
    /// Ed25519 scalars are little-endian, while the default trait helper treats
    /// its input as big-endian.
    fn from_bytes_mod_order(bytes: &[u8]) -> Self {
        let mut acc = Self::zero();
        let radix = Self::from_uint(Uint::from_u64(256));
        for &byte in bytes.iter().rev() {
            acc = acc.mul(&radix);
            acc = acc.add(&Self::from_uint(Uint::from_u64(byte as u64)));
        }
        acc
    }

    fn from_bytes_wide(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 64, "from_bytes_wide requires exactly 64 bytes");
        Self::from_bytes_mod_order(bytes)
    }
}

#[cfg(feature = "zeroize")]
impl zeroize::Zeroize for Ed25519Scalar {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
