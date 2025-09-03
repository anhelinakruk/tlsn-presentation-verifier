use hash::hash_body_fields;
use merkle::compute_header_root;
use signature::verify_signature;
use chacha_encoder::chacha_encoder::add_sixteen_elements;

pub mod hash;
pub mod merkle;
pub mod signature;  

pub fn main(
    signature_data: SignatureData,
    header_verification: HeaderVerification,
    transcript: TranscriptCommitment
) {
    // Message Verification
    let message_hash: [u8; 32] = sha256::sha256_var(signature_data.message, 54);
    let signature_valid = verify_signature(signature_data.key, message_hash, signature_data.signature);
    assert(signature_valid);

    // Header Verification
    let body_field_hashes = hash_body_fields(
        header_verification.verifying_key_data,
        header_verification.connection_info_data,
        header_verification.server_ephemeral_key_data,
        header_verification.cert_commitment_data,
        header_verification.transcript_commitments_data 
    );

    let computed_header_root = compute_header_root(body_field_hashes);
    assert(computed_header_root == header_verification.header_root);

    // Transcript Commitment Verification
    let transcript_with_blinder = add_sixteen_elements(transcript.data, transcript.blinder);
    let hash = sha256::sha256_var(transcript_with_blinder, 1190);
    print(hash);
    let mut transcript_commitment_hash: [u8; 32] = [0; 32];
    for i in 0..32 {
        transcript_commitment_hash[i] = header_verification.transcript_commitments_data[21 + i];
    }
    assert(hash == transcript_commitment_hash);
}

pub struct SignatureData {
    key: [u8; 64],
    message: [u8; 54],
    signature: [u8; 64],
}

pub struct HeaderVerification {
    header_root: [u8; 32],
    verifying_key_data: [u8; 35],
    connection_info_data: [u8; 17],
    server_ephemeral_key_data: [u8; 67],
    cert_commitment_data: [u8; 34],
    transcript_commitments_data: [u8; 53],
}

pub struct TranscriptCommitment {
    data: [u8; 1174],
    blinder: [u8; 16],
}

