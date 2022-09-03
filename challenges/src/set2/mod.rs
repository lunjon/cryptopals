use crypt::aes;
use crypt::encoding::{base64, Decoder};
use crypt::pad::pkcs7;
use crypt::util;
use crypt::Result;
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
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown = decoder.decode(&unknown_string).unwrap();
        let unknown = from_utf8(&unknown).unwrap().to_string();

        let key = aes::random_key();
        Self { unknown, key }
    }

    pub fn encrypt(&self, data: &str) -> Result<Vec<u8>> {
        let mut data = String::from(data);
        data.push_str(&self.unknown);
        let encrypted = aes::encrypt_128(aes::Mode::ECB, &data.as_bytes(), &self.key)?;
        Ok(encrypted)
    }
}

#[test]
fn challenge_12() -> Result<()> {
    let encrypter = Challenge12::new();

    // 1: detect block size
    let mut block_size = 0;
    let start_size = encrypter.encrypt("A")?.len();
    for n in 2..512 {
        let encrypted = encrypter.encrypt(&"A".repeat(n))?;
        if encrypted.len() != start_size {
            block_size = encrypted.len() - start_size;
            break;
        }
    }
    assert_eq!(16, block_size);

    // 2: detect AES mode (using the fact that ECB is deterministic)
    let input = "a".repeat(block_size * 2);
    let encrypted = encrypter.encrypt(&input)?;
    let mode = aes::detection_oracle(input.as_bytes(), &encrypted).unwrap();
    assert_eq!("ECB", mode);

    // 3
    let mut unknown: Vec<String> = Vec::new();

    // Should probably keep going, but the principle is the same
    for _ in 0..block_size {
        let initial_input = "A".repeat(block_size - unknown.len() - 1);
        let initial_encrypted = encrypter.encrypt(&initial_input)?;

        let initial_block = &initial_encrypted[0..block_size];
        let mut table: Vec<(String, Vec<u8>)> = Vec::new();

        for n in 0..256 {
            let ch = char::from_u32(n).expect("to have valid byte");
            // let input = format!("{}{}", initial_input, ch);
            let input = format!("{}{}{}", initial_input, unknown.join(""), ch);
            let enc = encrypter.encrypt(&input)?;
            let block = &enc[0..block_size];
            let key = format!("{}{}{}", initial_input, unknown.join(""), ch);
            table.push((key, block.to_vec()));
        }

        let mut found: Option<String> = None;
        for (input, enc) in &table {
            if util::slices_equal(&initial_block, enc) {
                let char = input.get(block_size - 1..block_size).unwrap();
                found = Some(char.to_string());
                break;
            }
        }

        let s = found.expect("to found next byte");
        unknown.push(s);
    }

    let unknown = unknown.join("");
    assert!(unknown.contains("Rollin'"));
    Ok(())
}

// Challenge 13

fn profile_for(email: &str) -> String {
    let email = email.replace("&", "").replace("=", "");
    format!("{email}&uid=10&role=user")
}

#[test]
fn challenge_13() {
    let email = "test@example.com";
    let profile = profile_for(email);
    assert!(profile.len() > 0);
}
