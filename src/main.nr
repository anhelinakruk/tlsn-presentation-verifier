use std::hash::blake3;

pub mod verify_signature;

pub fn compute_merkle_root<let N: u32>(
    leaf: [u8; 32],
    index: Field,
    hash_path: [[u8; 32]; N],
) -> [u8; 32] {
    let index_bits: [u1; N] = index.to_le_bits();
    let mut current = leaf;

    for i in 0..N {
        let path_bit = index_bits[i] as bool;
        let (hash_left, hash_right) = if path_bit {
            (hash_path[i], current)
        } else {
            (current, hash_path[i])
        };

        let mut input: [u8; 64] = [0; 64];
        for j in 0..32 {
            input[j] = hash_left[j];
            input[j + 32] = hash_right[j];
        }

        current = blake3(input);
    }
    current
}

pub fn verify_membership<let N: u32>(
    root: [u8; 32],
    leaf: [u8; 32],
    index: Field,
    hash_path: [[u8; 32]; N],
) {
    let computed_root = compute_merkle_root(leaf, index, hash_path);
    assert(computed_root == root);
}

pub fn main(
    key: [u8; 64],
    message_hash: [u8; 32],
    signature: [u8; 64],
    root: [u8; 32],
    leaves: [[u8; 32]; 5],
    indices: [Field; 5],
    hash_paths: [[[u8; 32]; 20]; 5],
) {
    let signature_valid = verify_signature::verify_signature(key, message_hash, signature);
    assert(signature_valid);

    for i in 0..5 {
        verify_membership(root, leaves[i], indices[i], hash_paths[i]);
    }
}
