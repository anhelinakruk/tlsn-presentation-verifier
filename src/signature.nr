pub fn verify_signature(key: [u8; 64], message_hash: [u8; 32], signature: [u8; 64]) -> bool {
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