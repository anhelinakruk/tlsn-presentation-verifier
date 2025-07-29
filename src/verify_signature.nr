use dep::std;
use sha256::sha256_var;

pub fn verify_signature<let N: u32>(
    key: [u8; 64],
    message: [u8; N],
    signature: [u8; 64],
    message_len: u64,
) -> bool {
    let mut pub_key_x: [u8; 32] = [0; 32];
    let mut pub_key_y: [u8; 32] = [0; 32];

    for i in 0..32 {
        pub_key_x[i] = key[i];
        pub_key_y[i] = key[i + 32];
    }

    let message_hash = sha256_var(message, message_len);

    let is_valid =
        std::ecdsa_secp256k1::verify_signature(pub_key_x, pub_key_y, signature, message_hash);

    assert(is_valid);

    true
}

#[test]
fn test_verify() {
    let key: [u8; 64] = [
        139, 217, 30, 31, 61, 245, 203, 158, 24, 36, 213, 244, 139, 246, 34, 254, 242, 248, 104, 45,
        141, 3, 255, 221, 31, 88, 9, 29, 214, 134, 222, 212, 169, 180, 129, 117, 182, 34, 105, 96,
        184, 38, 124, 119, 239, 6, 192, 103, 170, 88, 184, 87, 54, 131, 71, 23, 110, 196, 115, 152,
        181, 72, 232, 113,
    ];
    let message = [
        24, 187, 45, 85, 72, 201, 109, 78, 117, 29, 217, 248, 47, 231, 96, 12, 0, 0, 0, 0, 2, 32,
        57, 154, 244, 134, 152, 50, 107, 199, 210, 204, 8, 27, 7, 190, 101, 60, 140, 205, 53, 209,
        16, 144, 160, 218, 189, 55, 107, 8, 247, 22, 174, 89,
    ];
    let signature: [u8; 64] = [
        199, 74, 205, 205, 237, 39, 1, 40, 106, 95, 238, 225, 79, 147, 198, 137, 126, 182, 29, 142,
        28, 56, 54, 165, 106, 69, 224, 57, 122, 230, 67, 46, 0, 201, 73, 96, 132, 66, 36, 164, 25,
        180, 153, 180, 248, 149, 39, 9, 131, 64, 49, 134, 217, 145, 152, 133, 207, 252, 231, 242,
        116, 125, 112, 191,
    ];
    let message_len = 54;

    let result = verify_signature(key, message, signature, message_len);
    assert(result);
}
