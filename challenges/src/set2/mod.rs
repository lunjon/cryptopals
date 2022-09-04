use crypt::aes;
use crypt::encoding::{base64, Decoder};
use crypt::pad::pkcs7;
use crypt::util;
use crypt::{Error::DataError, Result};
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

struct C12 {
    unknown: String,
    key: Vec<u8>,
}

impl C12 {
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
    let encrypter = C12::new();

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

struct UserProfile {
    email: String,
    uid: String,
    role: String,
}

impl UserProfile {
    fn new(email: String, uid: String, role: String) -> Self {
        Self { email, uid, role }
    }

    fn encode(&self) -> String {
        format!("email={}&uid={}&role={}", self.email, self.uid, self.role)
    }

    fn profile_for(email: &str) -> Self {
        let email = email.replace("&", "").replace("=", "");
        Self::new(email, String::from("10"), String::from("user"))
    }
}

struct C13 {
    key: Vec<u8>,
}

impl C13 {
    fn new() -> Self {
        Self {
            key: aes::random_key(),
        }
    }

    fn encrypt(&self, p: &UserProfile) -> Result<Vec<u8>> {
        let data = p.encode();
        dbg!(&data);
        aes::encrypt_128(aes::Mode::ECB, data.as_bytes(), &self.key)
    }

    fn decrypt(&self, d: &[u8]) -> Result<UserProfile> {
        let decrypted = aes::decrypt_128(aes::Mode::ECB, d, &self.key)?;
        let s = from_utf8(&decrypted)?;

        let mut table: HashMap<String, String> = HashMap::new();

        let err = Err(DataError("invalid key/value pair".to_string()));
        for field in s.split("&") {
            let mut split = field.split("=");
            let key = match split.next() {
                Some(k) => k.to_string(),
                None => return err,
            };
            let val = match split.next() {
                Some(v) => v.to_string(),
                None => return err,
            };

            table.insert(key, val);
        }

        let email = match table.get("email") {
            Some(s) => s,
            None => return err,
        };
        let uid = match table.get("uid") {
            Some(s) => s,
            None => return Err(DataError("invalid key/value pair".to_string())),
        };
        let role = match table.get("role") {
            Some(s) => s,
            None => return err,
        };

        Ok(UserProfile::new(
            email.to_string(),
            uid.to_string(),
            role.to_string(),
        ))
    }
}

#[test]
fn challenge_13() -> Result<()> {
    let block_size = 16;
    let c13 = C13::new();

    // The solution lies in how ECB mode works:
    // Given a sequence of blocks, the plaintext blocks can be directly
    // correlated to the ciphertext blocks, and vice versa:
    // [ P 1 ][ P 2 ]...
    //    |      |
    //    v      v
    // [ C 1 ][ C 2 ]...
    //
    // The plan is to come up with an email string that allows us to:
    //   1) construct a user profile that yields clear block boundaries
    //   2) feed it to C13.encrypt
    //   3) cut and paste the encrypted blocks
    //   4) feed it to C13.decrypt
    //   5) get a user profile with role=admin

    // By using the profile_for function we get something like
    let p = UserProfile::profile_for("test@ex.com");
    assert_eq!("email=test@ex.com&uid=10&role=user", p.encode());

    // This will be encrypted as:
    // [email=test@ex.co][m&uid=10&role=us][er ... PKSC#7 padding]
    // Yielding also three blocks of ciphertext
    let e = c13.encrypt(&p)?;
    assert_eq!(block_size * 3, e.len());

    // Each ciphertext block (again, with ECB) can be decrypted by itself.
    // This means that we could re-arrange the blocks and then decrypt
    // it succesfully. However, to exploit this we need to construct an email
    // string that we feed to profile_for that yields encrypted blocks that
    // we can move around to also decrypt AND decode succesfully in C13.

    // Theory (X=padding by PKSC#7):
    //   hackery@evil.comadminXXXXXXXXXXXaaa
    //
    // Now:
    //   1) Feed the email to profile_for.
    //   2) Feed the profile to C13.encrypt.
    //      a) encoded blocks:
    //         [email=hack@e.com][adminXXXXXXXXXXX][aaa&uid=10&role=][user]
    //      b) encrypted blocks:
    //         [       A        ][       B        ][        C       ][       D        ]
    //   3) Having the encrypted profile:
    //     a) strip block D
    //     b) re-arrange the blocks: [ A ][ C ][ B ]
    //   4) Having the encrypted profile, feed the altered data to C13.decrypt

    // 1)
    let admin_block = pkcs7(b"admin", block_size);
    let email = format!("hack@e.com{}aaa", from_utf8(&admin_block)?);
    let profile = UserProfile::profile_for(&email);

    // 2)
    let encrypted = c13.encrypt(&profile)?;
    assert_eq!(block_size * 4, encrypted.len());

    // 3)
    let mut altered_data = Vec::new();
    altered_data.extend_from_slice(&encrypted[0..block_size]);
    altered_data.extend_from_slice(&encrypted[block_size * 2..block_size * 3]);
    altered_data.extend_from_slice(&encrypted[block_size..block_size * 2]);
    assert_eq!(block_size * 3, altered_data.len());

    let profile = c13.decrypt(&altered_data)?;
    assert_eq!("admin", profile.role);

    Ok(())
}
