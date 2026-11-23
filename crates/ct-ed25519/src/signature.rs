use crate::error::SignatureError;
use subtle::{Choice, ConstantTimeEq};

#[derive(Clone, Copy)]
pub struct Signature {
    bytes: [u8; 64],
}

impl Signature {
    pub const BYTE_SIZE: usize = 64;

    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        Self { bytes: *bytes }
    }

    pub fn to_bytes(&self) -> [u8; 64] {
        self.bytes
    }
    pub(crate) fn r_bytes(&self) -> &[u8; 32] {
        self.bytes[..32].try_into().unwrap()
    }
    pub(crate) fn s_bytes(&self) -> &[u8; 32] {
        self.bytes[32..].try_into().unwrap()
    }
}

impl ConstantTimeEq for Signature {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.bytes.ct_eq(&other.bytes)
    }
}

impl TryFrom<&[u8]> for Signature {
    type Error = SignatureError;
    fn try_from(b: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; 64] = b.try_into().map_err(|_| SignatureError)?;
        Ok(Self { bytes: arr })
    }
}
