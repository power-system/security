#![allow(dead_code)]

pub fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

pub fn hex_to_32(s: &str) -> [u8; 32] {
    hex_to_vec(s).try_into().unwrap()
}

pub fn hex_to_64(s: &str) -> [u8; 64] {
    hex_to_vec(s).try_into().unwrap()
}

pub fn hex_eq(bytes: &[u8], expected: &str) -> bool {
    hex::encode(bytes) == expected
}
