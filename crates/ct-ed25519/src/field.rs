use ct_fp::{PrimeField, helpers::conditional_sub_p};
use ct_uint::{Limb, Uint};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};

const MODULUS: Uint<4> = Uint::from_limbs([
    Limb::from_u64(0xFFFF_FFFF_FFFF_FFED),
    Limb::from_u64(0xFFFF_FFFF_FFFF_FFFF),
    Limb::from_u64(0xFFFF_FFFF_FFFF_FFFF),
    Limb::from_u64(0x7FFF_FFFF_FFFF_FFFF),
]);

#[derive(Clone, Copy, Debug)]
pub(crate) struct Ed25519Fp(pub(crate) Uint<4>);

impl ConstantTimeEq for Ed25519Fp {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl ConditionallySelectable for Ed25519Fp {
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self(Uint::conditional_select(&a.0, &b.0, c))
    }
}

impl Ed25519Fp {
    pub(crate) const ZERO: Self = Self(Uint::ZERO);
    pub(crate) const ONE: Self = Self(Uint::ONE);

    pub(crate) fn from_bytes(b: &[u8; 32]) -> Option<Self> {
        let v = Uint::<4>::from_le_bytes(b)?;
        let (_, underflow) = v.checked_sub(&MODULUS);
        if bool::from(underflow) {
            Some(Self(v))
        } else {
            None
        }
    }

    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        self.0.write_le_bytes(&mut out);
        out
    }

    pub(crate) fn is_negative(&self) -> Choice {
        Choice::from((self.to_bytes()[0] & 1) as u8)
    }
}

impl PrimeField<4> for Ed25519Fp {
    const MODULUS: Uint<4> = MODULUS;

    fn mul(&self, rhs: &Self) -> Self {
        let (lo, hi) = self.0.widening_mul(&rhs.0);
        let lo_l = lo.limbs();
        let hi_l = hi.limbs();

        let mut acc = [0u128; 4];
        for i in 0..4 {
            acc[i] = lo_l[i].to_u64() as u128 + 38u128 * hi_l[i].to_u64() as u128;
        }
        let mut r = [0u64; 4];
        let mut c: u128 = 0;
        for i in 0..4 {
            let v = acc[i] + c;
            r[i] = v as u64;
            c = v >> 64;
        }
        let mut extra: u128 = c * 38;
        for i in 0..4 {
            let v = r[i] as u128 + extra;
            r[i] = v as u64;
            extra = v >> 64;
            if extra == 0 {
                break;
            }
        }
        let mut extra2 = extra * 38;
        for i in 0..4 {
            if extra2 == 0 {
                break;
            }
            let v = r[i] as u128 + extra2;
            r[i] = v as u64;
            extra2 = v >> 64;
        }

        let raw = Uint::from_limbs([
            Limb::from_u64(r[0]),
            Limb::from_u64(r[1]),
            Limb::from_u64(r[2]),
            Limb::from_u64(r[3]),
        ]);
        let raw = conditional_sub_p(raw, &MODULUS);
        Self(conditional_sub_p(raw, &MODULUS))
    }

    fn from_uint(v: Uint<4>) -> Self {
        Self(conditional_sub_p(v, &MODULUS))
    }

    fn to_uint(&self) -> Uint<4> {
        self.0
    }
}

pub(crate) fn d() -> Ed25519Fp {
    Ed25519Fp::from_bytes(&[
        0xa3, 0x78, 0x59, 0x13, 0xca, 0x4d, 0xeb, 0x75, 0xab, 0xd8, 0x41, 0x41, 0x4d, 0x0a, 0x70,
        0x00, 0x98, 0xe8, 0x79, 0x77, 0x79, 0x40, 0xc7, 0x8c, 0x73, 0xfe, 0x6f, 0x2b, 0xee, 0x6c,
        0x03, 0x52,
    ])
    .unwrap()
}

pub(crate) fn two_d() -> Ed25519Fp {
    d().add(&d())
}

pub(crate) fn sqrt_m1() -> Ed25519Fp {
    Ed25519Fp::from_bytes(&[
        0xb0, 0xa0, 0x0e, 0x4a, 0x27, 0x1b, 0xee, 0xc4, 0x78, 0xe4, 0x2f, 0xad, 0x06, 0x18, 0x43,
        0x2f, 0xa7, 0xd7, 0xfb, 0x3d, 0x99, 0x00, 0x4d, 0x2b, 0x0b, 0xdf, 0xc1, 0x4f, 0x80, 0x24,
        0x83, 0x2b,
    ])
    .unwrap()
}

pub(crate) fn basepoint_x() -> Ed25519Fp {
    Ed25519Fp::from_bytes(&[
        0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c,
        0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36,
        0x69, 0x21,
    ])
    .unwrap()
}

pub(crate) fn basepoint_y() -> Ed25519Fp {
    let mut bytes = [0x66u8; 32];
    bytes[0] = 0x58;
    Ed25519Fp::from_bytes(&bytes).unwrap()
}
