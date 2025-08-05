use std::hash::blake3;

fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut input: [u8; 64] = [0; 64];
    for i in 0..32 {
        input[i] = left[i];
        input[i + 32] = right[i];
    }
    blake3(input)
}

fn compute_header_root(leaves: [[u8; 32]; 5]) -> [u8; 32] {
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

pub fn compute_commitment_root(leaves: [[u8; 32]; 9]) -> [u8; 32] {
    // Level 1
    let h0 = hash_pair(leaves[0], leaves[1]);
    let h1 = hash_pair(leaves[2], leaves[3]);
    let h2 = hash_pair(leaves[4], leaves[5]);
    let h3 = hash_pair(leaves[6], leaves[7]);
    let h4 = leaves[8];

    // Level 2
    let h5 = hash_pair(h0, h1);
    let h6 = hash_pair(h2, h3);
    let h7 = h4;

    let h8 = hash_pair(h5, h6);
    let h9 = h7;

    // Root
    let root = hash_pair(h8, h9);

    root
}

use dep::std;

fn verify_signature(key: [u8; 64], message_hash: [u8; 32], signature: [u8; 64]) -> bool {
    let mut pub_key_x: [u8; 32] = [0; 32];
    let mut pub_key_y: [u8; 32] = [0; 32];

    for i in 0..32 {
        pub_key_x[i] = key[i];
        pub_key_y[i] = key[i + 32];
    }

    let is_valid =
        std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash);

    is_valid
}

pub fn main(
    key: [u8; 64],
    message: [u8; 54],
    signature: [u8; 64],
    header_root: [u8; 32],
    body_leaves_hashes: [[u8; 32]; 5],
    commitment_root: [u8; 32],
    transcript_leaves_hashes: [[u8; 32]; 9],
) {
    let message_hash: [u8; 32] = sha256::sha256_var(message, 54);
    let signature_valid = verify_signature(key, message_hash, signature);
    assert(signature_valid);

    let computed_header_root = compute_header_root(body_leaves_hashes);
    assert(computed_header_root == header_root);

    let computed_commitment_root = compute_commitment_root(transcript_leaves_hashes);
    assert(computed_commitment_root == commitment_root);
}

#[test]
fn test_compute_merkle_root_from_leaves() {
    let leaves: [[u8; 32]; 5] = [
        [
            141, 104, 217, 155, 2, 30, 168, 170, 185, 6, 45, 127, 65, 176, 175, 228, 72, 218, 81,
            227, 93, 163, 206, 24, 140, 103, 224, 164, 152, 48, 38, 74,
        ],
        [
            216, 120, 202, 43, 151, 133, 16, 195, 221, 77, 11, 207, 7, 93, 224, 130, 183, 2, 47, 9,
            72, 248, 85, 27, 219, 47, 66, 250, 186, 72, 210, 240,
        ],
        [
            105, 174, 86, 34, 16, 193, 174, 244, 128, 94, 26, 62, 99, 215, 54, 61, 182, 58, 221,
            243, 57, 225, 236, 32, 110, 27, 178, 171, 3, 57, 204, 231,
        ],
        [
            221, 201, 199, 254, 14, 61, 213, 1, 24, 72, 19, 183, 8, 66, 227, 150, 117, 138, 144,
            205, 125, 177, 45, 15, 149, 21, 252, 142, 147, 111, 79, 196,
        ],
        [
            230, 33, 57, 199, 150, 131, 62, 144, 32, 2, 162, 131, 154, 153, 139, 171, 103, 231, 107,
            57, 102, 255, 146, 74, 215, 142, 121, 39, 89, 2, 112, 67,
        ],
    ];

    let expected_root = [
        159, 84, 217, 98, 224, 139, 152, 197, 11, 87, 166, 82, 38, 181, 140, 115, 86, 135, 126, 231,
        230, 58, 104, 152, 192, 174, 80, 163, 201, 166, 74, 206,
    ];

    let actual_root = compute_header_root(leaves);

    assert(expected_root == actual_root);
}

#[test]
fn test_compute_merkle_root_from_leaves_nine() {
    let leaves: [[u8; 32]; 9] = [
        [
            89, 213, 174, 100, 184, 37, 136, 243, 214, 156, 194, 1, 89, 126, 48, 163, 186, 136, 229,
            132, 255, 119, 63, 14, 234, 30, 3, 77, 163, 212, 146, 40,
        ],
        [
            68, 169, 184, 177, 243, 187, 28, 190, 16, 224, 139, 4, 168, 215, 175, 122, 116, 56, 139,
            217, 201, 243, 253, 207, 219, 211, 9, 139, 95, 10, 11, 105,
        ],
        [
            109, 161, 215, 124, 153, 38, 206, 196, 154, 168, 163, 58, 21, 66, 36, 97, 77, 188, 201,
            241, 120, 124, 6, 24, 102, 144, 185, 173, 188, 253, 183, 156,
        ],
        [
            69, 248, 10, 26, 230, 252, 12, 41, 46, 67, 102, 123, 174, 32, 217, 66, 49, 114, 189,
            255, 89, 233, 232, 149, 119, 10, 133, 130, 130, 162, 22, 49,
        ],
        [
            64, 46, 57, 207, 221, 208, 154, 44, 22, 224, 41, 163, 204, 96, 240, 234, 56, 20, 249,
            166, 148, 94, 183, 146, 6, 142, 194, 235, 195, 11, 213, 162,
        ],
        [
            189, 112, 230, 54, 80, 112, 220, 32, 109, 129, 56, 124, 218, 82, 112, 91, 170, 56, 50,
            122, 233, 202, 176, 141, 201, 20, 4, 67, 228, 0, 42, 160,
        ],
        [
            125, 204, 131, 41, 94, 159, 251, 246, 110, 86, 212, 249, 124, 124, 192, 134, 206, 155,
            250, 47, 2, 28, 197, 239, 250, 186, 6, 68, 16, 134, 23, 226,
        ],
        [
            239, 93, 140, 226, 180, 63, 23, 240, 179, 198, 40, 0, 173, 35, 12, 67, 165, 153, 84, 35,
            76, 127, 128, 134, 3, 18, 67, 97, 251, 148, 156, 26,
        ],
        [
            74, 70, 53, 238, 208, 187, 238, 80, 35, 243, 105, 111, 127, 193, 183, 184, 171, 21, 136,
            56, 43, 62, 146, 181, 94, 75, 240, 40, 186, 249, 69, 93,
        ],
    ];

    let expected_root = [
        17, 201, 148, 157, 99, 14, 220, 117, 64, 238, 156, 33, 126, 34, 131, 178, 224, 198, 179, 44,
        220, 232, 159, 216, 115, 90, 246, 68, 245, 36, 117, 66,
    ];

    let actual_root = compute_commitment_root(leaves);

    assert(expected_root == actual_root);
}
