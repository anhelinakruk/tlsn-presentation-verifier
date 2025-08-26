use super::hash::hash_pair;
use chacha_encoder::chacha_encoder::{add_sixteen_elements, encode_data_generic_byte, EncoderSecret};

pub fn compute_commitment_root(leaves: [[u8; 32]; 4]) -> [u8; 32] {
    // Level 1
    let h0 = hash_pair(leaves[0], leaves[1]);
    let h1 = hash_pair(leaves[2], leaves[3]);
    
    // Root
    let root = hash_pair(h0, h1);

    root
}

pub fn compute_header_root(leaves: [[u8; 32]; 5]) -> [u8; 32] {
    // Level 1
    let h0 = hash_pair(leaves[0], leaves[1]);
    let h1 = hash_pair(leaves[2], leaves[3]);
    let h2 = leaves[4];

    // Level 2
    let h3 = hash_pair(h0, h1);

    // Root
    let root = hash_pair(h3, h2);

    root
}

pub fn encode_and_hash<let N: u32>(encoder_secret: EncoderSecret, data: [u8; N], direction: u8, position: u32, blinder: [u8; 16]) -> [u8; 32] {
    let encoded_data = encode_data_generic_byte(encoder_secret, direction ,position, data);

    let encoded_with_blinder = add_sixteen_elements
    (encoded_data, blinder);

    let hash = sha256::sha256_var(encoded_with_blinder, encoded_with_blinder.len() as u64);
    hash
}
