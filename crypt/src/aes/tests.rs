use super::*;

const KEY: &[u8] = b"YELLOW SUBMARINE";

#[test]
fn test_encrypt_128_ecb() {
    let data = b"Some Crypto Text";
    let encrypted = encrypt_128(Mode::ECB, data, KEY).unwrap();
    assert!(encrypted.len() > 0);
}

#[test]
fn test_encrypt_128_cbc() {
    let data = b"Some Crypto Text";

    let encrypted = encrypt_128(Mode::CBC(KEY.to_vec()), data, KEY).unwrap();
    assert!(encrypted.len() > 0);
}

#[test]
fn test_encrypt_oracle() {
    let data = b"Some Crypto Text and something else";
    let (encrypted, _) = encrypt_oracle(data).unwrap();
    assert!(encrypted.len() > 0);
}

#[test]
fn test_decrypt_128_ecb() {
    let data = b"Some Crypto Text";

    let encrypted = encrypt_128(Mode::ECB, data, KEY).unwrap();
    let decrypted = decrypt_128(Mode::ECB, &encrypted, KEY).unwrap();
    assert_eq!(decrypted, data);
}

#[test]
fn test_decrypt_128_cbc() {
    let data = b"Some Crypto Text";

    let encrypted = encrypt_128(Mode::CBC(KEY.to_vec()), data, KEY).unwrap();
    let decrypted = decrypt_128(Mode::CBC(KEY.to_vec()), &encrypted, KEY).unwrap();
    assert_eq!(decrypted, data);
}
