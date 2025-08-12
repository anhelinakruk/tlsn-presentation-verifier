use hash::hash_body_fields;
use merkle::{encode_and_hash, compute_header_root, compute_commitment_root};
use signature::verify_signature;
use chacha_encoder::chacha_encoder::{EncoderSecret};

pub mod hash;
pub mod merkle;
pub mod signature;  

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
    transcript_amount: TranscriptOpeningAmount,
    transcript_comment: TranscriptOpeningComment,
    transcript_user_name: TranscriptOpeningUserName,
    transcript_currency: TranscriptOpeningCurrency,
    encoder_secret: EncoderSecret
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

    let mut commitment_leaves_hash: [[u8; 32]; 4] = [[0; 32]; 4];
    
    commitment_leaves_hash[0] = encode_and_hash(encoder_secret, transcript_amount.data, transcript_amount.direction, transcript_amount.position, transcript_amount.blinders);
    commitment_leaves_hash[1] = encode_and_hash(encoder_secret, transcript_comment.data, transcript_comment.direction, transcript_comment.position, transcript_comment.blinders);
    commitment_leaves_hash[2] = encode_and_hash(encoder_secret, transcript_user_name.data, transcript_user_name.direction, transcript_user_name.position, transcript_user_name.blinders);
    commitment_leaves_hash[3] = encode_and_hash(encoder_secret, transcript_currency.data, transcript_currency.direction, transcript_currency.position, transcript_currency.blinders);

    let computed_commitment_root = compute_commitment_root(commitment_leaves_hash);
    assert(computed_commitment_root == commitment_root);
}

pub struct TranscriptOpeningAmount {
    direction: u64,
    data: [u8; 16],
    blinders: [u8; 16],
    position: u32,
}

pub struct TranscriptOpeningUserName {
    direction: u64,
    data: [u8; 28],
    blinders: [u8; 16],
    position: u32,
}

pub struct TranscriptOpeningComment {
    direction: u64,
    data: [u8; 23],
    blinders: [u8; 16],
    position: u32,  
}

pub struct TranscriptOpeningCurrency {
    direction: u64,
    data: [u8; 12],
    blinders: [u8; 16],
    position: u32,
}
