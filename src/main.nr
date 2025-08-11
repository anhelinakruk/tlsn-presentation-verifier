use std::hash::blake3;
use dep::std;

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

fn hash_domain<let N: u32>(domain_bytes: [u8; N]) -> [u8; 16] {
    let domain_hash = blake3(domain_bytes);
    let mut domain: [u8; 16] = [0; 16];
    
    for i in 0..16 {
        domain[i] = domain_hash[i];
    }
    
    domain
}

fn hash_field<let N: u32>(domain: [u8; 16], data: [u8; N]) -> [u8; 32] {
    let mut input: [u8; 16 + N] = [0; 16 + N]; 
    
    for i in 0..16 {
        input[i] = domain[i];
    }
    
    for i in 0..N {
        input[i + 16] = data[i];
    }
    
    blake3(input)
}

fn hash_body_fields(
    verifying_key_data: [u8; 35],
    connection_info_data: [u8; 17],
    server_ephemeral_key_data: [u8; 67],
    cert_commitment_data: [u8; 34],
    transcript_commitments_data: [u8; 83]
) -> [[u8; 32]; 5] {
    let mut body_field_hashes: [[u8; 32]; 5] = [[0; 32]; 5];

    body_field_hashes[0] = hash_field(hash_domain("VerifyingKey".as_bytes()), verifying_key_data);
    body_field_hashes[1] = hash_field(hash_domain("ConnectionInfo".as_bytes()), connection_info_data);
    body_field_hashes[2] = hash_field(hash_domain("ServerEphemKey".as_bytes()), server_ephemeral_key_data);
    body_field_hashes[3] = hash_field(hash_domain("ServerCertCommitment".as_bytes()), cert_commitment_data);
    body_field_hashes[4] = hash_field(hash_domain("TranscriptCommitment".as_bytes()), transcript_commitments_data);

    body_field_hashes
}

pub fn main(

    key: [u8; 64],
    message: [u8; 54],
    signature: [u8; 64],
    header_root: [u8; 32],
    verifying_key_data: [u8; 35],
    connection_info_data: [u8; 17],
    server_ephemeral_key_data: [u8; 67],
    cert_commitment_data: [u8; 34],
    transcript_commitments_data: [u8; 83],
    commitment_root: [u8; 32],
    transcript_leaves: [[u8; 3000]; 9], 
    leaves_lengths: [u32; 9],            
) {
    let message_hash: [u8; 32] = sha256::sha256_var(message, 54);
    let signature_valid = verify_signature(key, message_hash, signature);
    assert(signature_valid);

    let body_field_hashes = hash_body_fields(
        verifying_key_data,
        connection_info_data,
        server_ephemeral_key_data,
        cert_commitment_data,
        transcript_commitments_data
    );

    let computed_header_root = compute_header_root(body_field_hashes);
    assert(computed_header_root == header_root);

    // let mut commitment_leaves_hash: [[u8; 32]; 9] = [[0; 32]; 9];
    // for i in 0..9 {
    //     let leaf_length = leaves_lengths[i];
    //     let hash =  hash_transcript_chunk(transcript_leaves[i], [0; leaf_length]);
    //     commitment_leaves_hash[i] = hash;
    // }

    // let computed_commitment_root = compute_commitment_root(commitment_leaves_hash);
    // assert(computed_commitment_root == commitment_root);
}

#[test]
fn test_hashed() {
    let verifying_key_data = [1, 33, 3, 236, 101, 149, 63, 171, 51, 123, 233, 63, 78, 214, 174, 228, 1, 149, 102, 240, 182, 253, 134, 215, 113, 106, 71, 237, 207, 177, 218, 180, 177, 28, 254];
    let connection_info_data =[141, 232, 140, 104, 0, 0, 0, 0, 0, 226, 0, 0, 0, 82, 3, 0, 0];
    let server_ephemeral_key_data = [0, 65, 4, 240, 11, 163, 35, 244, 238, 130, 219, 134, 219, 252, 69, 190, 78, 127, 23, 220, 25, 168, 37, 192, 152, 124, 5, 5, 58, 129, 139, 79, 37, 153, 31, 144, 209, 51, 141, 170, 143, 239, 70, 46, 164, 136, 41, 165, 4, 54, 73, 46, 52, 249, 215, 148, 119, 59, 141, 67, 102, 10, 176, 166, 3, 222, 207];
    let cert_commitment_data = [2, 32, 183, 33, 154, 74, 47, 217, 70, 119, 20, 62, 78, 177, 146, 124, 244, 189, 202, 203, 125, 69, 154, 85, 27, 206, 38, 17, 140, 120, 97, 99, 14, 175];
    let transcript_commitments_data = [0, 2, 32, 70, 38, 119, 62, 85, 14, 143, 50, 9, 72, 172, 242, 248, 100, 145, 2, 139, 207, 135, 7, 29, 38, 115, 244, 170, 58, 194, 255, 143, 217, 148, 55, 248, 220, 245, 20, 169, 36, 114, 114, 204, 66, 91, 5, 152, 76, 158, 216, 150, 18, 189, 77, 231, 57, 140, 238, 123, 130, 55, 28, 205, 237, 148, 46, 209, 82, 79, 84, 142, 193, 90, 159, 255, 172, 58, 16, 72, 116, 154, 2];

    let body_hashed = hash_body_fields(verifying_key_data, connection_info_data, server_ephemeral_key_data, cert_commitment_data, transcript_commitments_data); 
    println(body_hashed);
}
