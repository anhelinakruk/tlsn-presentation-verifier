use std::hash::blake3;

pub fn hash_pair(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut input: [u8; 64] = [0; 64];
    for i in 0..32 {
        input[i] = left[i];
        input[i + 32] = right[i];
    }
    blake3(input)
}

pub fn hash_body_fields(
    verifying_key_data: [u8; 35],
    connection_info_data: [u8; 17],
    server_ephemeral_key_data: [u8; 67],
    cert_commitment_data: [u8; 34],
    transcript_commitments_data: [u8; 53]
) -> [[u8; 32]; 5] {
    let mut body_field_hashes: [[u8; 32]; 5] = [[0; 32]; 5];

    body_field_hashes[0] = hash_field(hash_domain("VerifyingKey".as_bytes()), verifying_key_data);
    body_field_hashes[1] = hash_field(hash_domain("ConnectionInfo".as_bytes()), connection_info_data);
    body_field_hashes[2] = hash_field(hash_domain("ServerEphemKey".as_bytes()), server_ephemeral_key_data);
    body_field_hashes[3] = hash_field(hash_domain("ServerCertCommitment".as_bytes()), cert_commitment_data);
    body_field_hashes[4] = hash_field(hash_domain("TranscriptCommitment".as_bytes()), transcript_commitments_data);

    body_field_hashes
}


pub fn hash_domain<let N: u32>(domain_bytes: [u8; N]) -> [u8; 16] {
    let domain_hash = blake3(domain_bytes);
    let mut domain: [u8; 16] = [0; 16];
    
    for i in 0..16 {
        domain[i] = domain_hash[i];
    }
    
    domain
}

pub fn hash_field<let N: u32>(domain: [u8; 16], data: [u8; N]) -> [u8; 32] {
    let mut input: [u8; 16 + N] = [0; 16 + N]; 
    
    for i in 0..16 {
        input[i] = domain[i];
    }
    
    for i in 0..N {
        input[i + 16] = data[i];
    }
    
    blake3(input)
}