#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SignatureError;

impl core::fmt::Display for SignatureError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("invalid Ed25519 key or signature encoding")
    }
}

impl core::error::Error for SignatureError {}

impl From<SignatureError> for signature::Error {
    fn from(_: SignatureError) -> Self {
        Self::new()
    }
}
