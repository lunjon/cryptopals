use crypt::aes;
use crypt::encoding::{base64, Decoder};
use crypt::pad::pkcs7;
use crypt::util;
use crypt::Result;
use std::collections::HashMap;
use std::str::from_utf8;

#[test]
fn challenge_9() {
    let before = b"YELLOW SUBMARINE";
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    let actual = pkcs7(before, 20);
    assert_eq!(actual, expected);
}

#[test]
fn challenge_10() -> Result<()> {
    // Arrange
    let key = b"YELLOW SUBMARINE";
    let iv = b"\x00".repeat(16).to_vec();

    let data_b64 = include_str!("../../data/set2_challenge10.txt");
    let data_b64 = util::into_line(data_b64);

    let decoder = base64::Base64::new();
    let data = decoder.decode(&data_b64)?;

    // Act
    let decrypted = aes::decrypt_128(aes::Mode::CBC(iv), &data, key)?;

    // Assert
    let decrypted_string = from_utf8(&decrypted)?;
    assert!(decrypted_string.contains("Vanilla"));
    Ok(())
}

#[test]
fn challenge_11() {
    for _ in 0..10 {
        // Black-box encryption
        let data_str = String::from("16bytesofpower!!").repeat(6);
        let data_bytes = data_str.as_bytes();
        let (encrypted, t) = aes::encrypt_oracle(data_bytes).unwrap();
        let actual_mode = if t { "ECB" } else { "CBC" };

        // Detection oracle
        let detected_mode = aes::detection_oracle(data_bytes, &encrypted).unwrap();
        assert_eq!(actual_mode, detected_mode);
    }
}

// Challenge 12

struct Challenge12 {
    unknown: String,
    key: Vec<u8>,
}

impl Challenge12 {
    fn new() -> Self {
        let decoder = base64::Base64::new();
        let unknown_string = util::into_line(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK",
        );
        let unknown = decoder.decode(&unknown_string).unwrap();
        let unknown = from_utf8(&unknown).unwrap().to_string();

        let key = aes::random_key();
        Self { unknown, key }
    }

    pub fn encrypt(&self, data: &str) -> Result<(String, Vec<u8>)> {
        let mut appended = String::from(data);
        appended.push_str(&self.unknown);

        let mut v: Vec<u8> = Vec::new();
        // v.extend(aes::random_data(5..11)); // do this here?
        v.extend(appended.as_bytes());
        // v.extend(aes::random_data(5..11)); // do this here?

        let encrypted = aes::encrypt_128(aes::Mode::ECB, &v, &self.key)?;
        Ok((appended, encrypted))
    }
}

fn detect_bock_size(_data: &[u8]) -> usize {
    // ??
    16
}

#[test]
fn challenge_12() -> Result<()> {
    let alphas = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    let encrypter = Challenge12::new();

    // 1
    let input_str = "A";
    // let input_bytes = input_str.as_bytes();
    let (_data_with_unknown, encrypted) = encrypter.encrypt(input_str)?;
    let block_size = detect_bock_size(&encrypted);
    // assert_eq!(16, block_size);

    // 2 - FIXME: detects wrong mode
    // let mode = aes::detection_oracle(data_with_unknown.as_bytes(), &encrypted).unwrap();
    // assert_eq!("ECB", mode);

    // 3
    let input_block_short = "A".repeat(block_size - 1);
    let (_, blah) = encrypter.encrypt(&input_block_short)?;
    let blah = &blah[0..block_size];

    let mut table: HashMap<String, String> = HashMap::new();

    for ch in alphas.chars() {
        let input_block = format!("{}{}", input_block_short, ch);
        let (_, enc) = encrypter.encrypt(&input_block)?;
        let enc = from_utf8(&enc[0..block_size])?;
        table.insert(enc.to_string(), input_block);
    }

    dbg!(table.get(&blah));
    assert!(false);
    Ok(())
}
