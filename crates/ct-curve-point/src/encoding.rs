use subtle::Choice;

pub trait PointEncoding: Sized {
    const COMPRESSED_LEN: usize;
    const UNCOMPRESSED_LEN: usize;

    fn from_compressed(bytes: &[u8]) -> Option<Self>;

    fn from_uncompressed(bytes: &[u8]) -> Option<Self>;

    fn to_compressed(&self, out: &mut [u8]);

    fn to_uncompressed(&self, out: &mut [u8]);

    fn ct_is_valid(&self) -> Choice;
}
