use super::hash::hash_pair;
use chacha_encoder::chacha_encoder::{encode_data_generic_byte, EncoderSecret};
use std::hash::blake3;

pub fn compute_commitment_root(leaves: [[u8; 32]; 3]) -> [u8; 32] {
    // Level 1
    let h0 = hash_pair(leaves[0], leaves[1]);
    let h1 = leaves[2];
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

    let hash = blake3(encoded_with_blinder);
    hash
}

pub fn add_sixteen_elements<let INPUT_SIZE: u32>(
    input: [u8; INPUT_SIZE],
    additional_elements: [u8; 16],
) -> [u8; INPUT_SIZE + 16] {
    // Verify that OUTPUT_SIZE = INPUT_SIZE + 16

    let mut result = [0; INPUT_SIZE + 16];

    // Copy original data
    for i in 0..INPUT_SIZE {
        result[i] = input[i];
    }

    // Add the 16 additional elements at the end
    for i in 0..16 {
        result[INPUT_SIZE + i] = additional_elements[i];
    }

    result
}
