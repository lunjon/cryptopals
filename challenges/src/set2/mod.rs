use crypt::aes;
use crypt::encoding::{base64, Decoder};
use crypt::pad::pkcs7;
use crypt::Result;
use std::str::from_utf8;

// Takes a multiline string and joines all into a single line.
fn into_line(s: &str) -> String {
    let lines: Vec<String> = s
        .trim()
        .lines()
        .map(|line| line.trim().to_string())
        .collect();
    lines.join("")
}

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
    let data_b64 = into_line(data_b64);

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
        let data = String::from("16bytesofpower!!").repeat(6);
        let (encrypted, t) = aes::encrypt_oracle(data.as_bytes()).unwrap();
        let actual_mode = if t { "ECB" } else { "CBC" };

        // Detection oracle
        let detected_mode = aes::detection_oracle(&encrypted).unwrap();
        assert_eq!(actual_mode, detected_mode);
    }
}
