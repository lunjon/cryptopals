use crypt::aes;
use crypt::encoding::{base64, Decoder};
use crypt::gen;
use crypt::pad::{pkcs7, pkcs7_validate};
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

struct C12 {
    unknown: String,
    key: Vec<u8>,
    prefix: Option<Vec<u8>>,
}

impl C12 {
    /// Returns a new oracle used in challenge 12 & 14.
    /// `prefix_random` is used by challenge 14 to append
    /// some random bytes before encrypting.
    fn new(prefix_random: bool) -> Self {
        let decoder = base64::Base64::new();
        let unknown_string = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK";
        let unknown = decoder.decode(&unknown_string).unwrap();
        let unknown = from_utf8(&unknown).unwrap().to_string();

        let prefix = if prefix_random {
            Some(gen::random_data(3..15))
        } else {
            None
        };

        let key = gen::random_key();
        Self {
            unknown,
            key,
            prefix,
        }
    }

    pub fn encrypt(&self, data: &str) -> Result<Vec<u8>> {
        let mut data_bytes = Vec::new();
        if let Some(prefix) = &self.prefix {
            data_bytes.extend_from_slice(prefix);
        }

        let mut data_string = String::from(data);
        data_string.push_str(&self.unknown);
        data_bytes.extend_from_slice(data_string.as_bytes());

        let es = aes::encrypt_128(aes::Mode::ECB, &data_bytes, &self.key)?;
        Ok(es)
    }

    pub fn prefix_len(&self) -> usize {
        self.prefix.as_ref().unwrap().len()
    }
}

#[test]
fn challenge_12() -> Result<()> {
    let encrypter = C12::new(false);

    // 1: detect block size (and length of target bytes)
    let mut block_size = 0;
    let mut target_bytes_length = 0;
    let start_size = encrypter.encrypt("")?.len();
    for n in 1..512 {
        let encrypted = encrypter.encrypt(&"A".repeat(n))?;
        if encrypted.len() != start_size {
            block_size = encrypted.len() - start_size;
            target_bytes_length = n - 1;
            break;
        }
    }

    assert_eq!(16, block_size);

    // 2: detect AES mode (using the fact that ECB is deterministic)
    let input = "a".repeat(block_size * 2);
    let encrypted = encrypter.encrypt(&input)?;
    let mode = aes::detection_oracle(input.as_bytes(), &encrypted).unwrap();
    assert_eq!("ECB", mode);

    // 3: find the random string, one byte at a time
    let mut target_bytes: Vec<String> = Vec::new();

    // Do like this:
    //   1. Begin by building a string that has a length of block_size - 1:
    //      Lets say that block size is 8, we begin with: "AAAAAAA"
    //   2. Feed the string to the oracle and save the first block of ciphertext.
    //      Before encryption the first block will look like: AAAAAAA?,
    //      i.e the last byte is unknown and the first byte of the target bytes.
    //   3. Now, constuct a string ending with every possible byte
    //      and feed that to the oracle, building a list of (input, block) pairs.
    //   4. Find the input, in your list created in step 3, that
    //      yields the same first block.
    //   5. Repeat step 1-4, but with the known byte at last position,
    //      and so on.
    //
    // After a while we have found the first block of the target bytes.
    // By then we will have to keep going with the same principle, but

    // Should probably keep going, but the principle is the same
    for _ in 0..block_size {
        let initial_input = "A".repeat(block_size - target_bytes.len() - 1);
        let initial_encrypted = encrypter.encrypt(&initial_input)?;

        let initial_block = &initial_encrypted[0..block_size];
        let mut table: Vec<(String, Vec<u8>)> = Vec::new();

        for n in 0..256 {
            let ch = char::from_u32(n).expect("to have valid byte");
            let input = format!("{}{}{}", initial_input, target_bytes.join(""), ch);
            let enc = encrypter.encrypt(&input)?;
            let block = &enc[0..block_size];
            table.push((input, block.to_vec()));
        }

        let mut found: Option<String> = None;
        for (input, enc) in &table {
            if util::slices_equal(&initial_block, enc) {
                let char = input.get(block_size - 1..block_size).unwrap();
                found = Some(char.to_string());
                break;
            }
        }

        let s = found.expect("to found next char");
        target_bytes.push(s);
    }

    let unknown = target_bytes.join("");
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
            key: gen::random_key(),
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
    let email = format!("hack@evil.{}com", from_utf8(&admin_block)?);
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

#[test]
// Byte-at-a-time ECB decryption (Harder)
fn challenge_14() -> Result<()> {
    // Same as in #12, but harder: the oracle now append random data before doing the rest
    let oracle = C12::new(true);

    // Skip step 1 & 2 (refer to #12 for that)
    let block_size = 16;

    // We now have: AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
    // Same goal: decrypt the target-bytes.
    //
    // The hardest part here is to find the prefix length, then
    // we can use the same procedure as in ch. 12.

    // Image feeding the following data to the oracle: "",  "x", "xx", etc.
    // We would get something like this, before it is encrypted:
    // [ random-prefix ][ target-bytes ]
    // [ random-prefix ]x[ target-bytes ]
    // [ random-prefix ]xx[ target-bytes ]
    // [ random-prefix ]xxx[ target-bytes ]
    // [ random-prefix ]xxxx[ target-bytes ]
    //
    // For each such input and the first block of ciphertext varies,
    // we have know that the x's are appended in the same block.
    // If, however, for two inputs of x's, say n and m, know that
    // n is the amount of padding before a new block was added:
    // [ P ][ xxx ][ T ... ]
    // [ P ][ xxx ][ xT ... ]

    let mut padding_len = 0;
    let a = oracle.encrypt("")?;
    let mut previous = a.get(0..16).unwrap().to_vec().clone();
    for n in 1..block_size {
        let b = oracle.encrypt(&"x".repeat(n))?;
        let x = &b[0..16];
        if util::slices_equal(&previous, &x) {
            padding_len = n - 1;
            break;
        }
        previous = x.to_vec().clone();
    }

    assert_ne!(padding_len, 0);
    let prefix_len = block_size - padding_len;
    assert_eq!(prefix_len, oracle.prefix_len()); // Sanity check
    let skip_len = prefix_len + padding_len;

    // See ch. 12 for reference.
    let mut unknown: Vec<String> = Vec::new();

    // Should probably keep going, but the principle is the same
    for _ in 0..block_size {
        let initial_input = "x".repeat(padding_len + block_size - unknown.len() - 1);
        let initial_encrypted = oracle.encrypt(&initial_input)?;
        let initial_block = &initial_encrypted[skip_len..skip_len + block_size];

        let mut table: Vec<(String, Vec<u8>)> = Vec::new();
        for n in 0..256 {
            let ch = char::from_u32(n).expect("to have valid byte");
            let input = format!("{}{}{}", initial_input, unknown.join(""), ch);
            let enc = oracle.encrypt(&input)?;
            let block = &enc[skip_len..skip_len + block_size];
            table.push((input, block.to_vec()));
        }

        let mut found: Option<String> = None;
        for (input, enc) in &table {
            if util::slices_equal(&initial_block, enc) {
                let char = input.chars().last().unwrap();
                found = Some(char.to_string());
                break;
            }
        }

        let s = found.expect("to found next char");
        unknown.push(s);
    }

    let unknown = unknown.join("");
    assert!(unknown.contains("Rollin'"));
    Ok(())
}

#[test]
fn challenge_15() {
    let res = pkcs7_validate("test\x04\x04\x04\x04", 8);
    assert!(res.is_ok());
    let res = pkcs7_validate("test\x04\x04\x04", 8);
    assert!(res.is_err());
}
