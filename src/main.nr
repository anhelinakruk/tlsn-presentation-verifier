use chacha_encoder::chacha_encoder::EncoderSecret;
use hash::hash_body_fields;
use merkle::{compute_commitment_root, compute_header_root, encode_and_hash};
use signature::verify_signature;

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
    transcript_mins: TranscriptOpeningMins,
    transcript_close_time: TranscriptOpeningCloseTime,
    transcript_price: TranscriptOpeningPrice,
    encoder_secret: EncoderSecret,
) {
    let message_hash: [u8; 32] = sha256::sha256_var(message, 54);
    let signature_valid = verify_signature(key, message_hash, signature);
    assert(signature_valid);

    let body_field_hashes = hash_body_fields(
        verifying_key_data,
        connection_info_data,
        server_ephemeral_key_data,
        cert_commitment_data,
        transcript_commitments_data,
    );

    let computed_header_root = compute_header_root(body_field_hashes);
    assert(computed_header_root == header_root);

    let mut commitment_leaves_hash: [[u8; 32]; 3] = [[0; 32]; 3];

    commitment_leaves_hash[0] = encode_and_hash(
        encoder_secret,
        transcript_mins.data,
        transcript_mins.direction,
        transcript_mins.position,
        transcript_mins.blinders,
    );
    println(commitment_leaves_hash[0]);
    commitment_leaves_hash[1] = encode_and_hash(
        encoder_secret,
        transcript_close_time.data,
        transcript_close_time.direction,
        transcript_close_time.position,
        transcript_close_time.blinders,
    );
    println(commitment_leaves_hash[1]);
    commitment_leaves_hash[2] = encode_and_hash(
        encoder_secret,
        transcript_price.data,
        transcript_price.direction,
        transcript_price.position,
        transcript_price.blinders,
    );
    println(commitment_leaves_hash[2]);

    let computed_commitment_root = compute_commitment_root(commitment_leaves_hash);
    assert(computed_commitment_root == commitment_root);
}

pub struct TranscriptOpeningPrice {
    direction: u8,
    data: [u8; 20],
    blinders: [u8; 16],
    position: u32,
}

pub struct TranscriptOpeningMins {
    direction: u8,
    data: [u8; 8],
    blinders: [u8; 16],
    position: u32,
}

pub struct TranscriptOpeningCloseTime {
    direction: u8,
    data: [u8; 25],
    blinders: [u8; 16],
    position: u32,
}
