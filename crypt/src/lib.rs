use crate::encoding::Decoder;
use crate::op::*;
use std::collections::{BTreeMap, HashMap};
use std::str::from_utf8;

pub mod aes;
pub mod encoding;
pub mod op;
pub mod pad;
pub mod util;

#[derive(Debug)]
pub enum Error {
    /// Indicates an argument/parameter to a function was invalid.
    ArgError(String),
    DataError(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::ArgError(s) => write!(f, "invalid argument: {}", s),
            Error::DataError(s) => write!(f, "invalid data: {}", s),
        }
    }
}

impl From<std::str::Utf8Error> for Error {
    fn from(err: std::str::Utf8Error) -> Self {
        Self::DataError(format!("error encoding as UTF-8: {}", err))
    }
}

/// Macro useful for returning errors.
#[macro_export]
macro_rules! data_err {
    ( $msg:expr ) => {
        crate::Error::DataError($msg.to_string())
    };
    ( $fmt:literal, $($e:expr),* ) => {
        crate::Error::DataError(format!($fmt, $($e),*))
    };
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Hacker {
    pub hex: encoding::hex::Hex,
    pub b64: encoding::base64::Base64,
    ascii_digits: Vec<u8>,
    common_letters: HashMap<char, usize>,
}

impl Hacker {
    pub fn new() -> Self {
        let mut ascii_digits: Vec<u8> = Vec::new(); // Decimal values of ASCII chars
        for i in 32..=123 {
            ascii_digits.push(i);
        }

        // Letters sorted after the most frequent, and
        // more frequent means higher weight/score.
        let most_common_letters = "etaoinshrdlcumwfgypbvkjxqz";
        let mut weight = most_common_letters.len();
        let mut common_letters = HashMap::new();
        for ch in most_common_letters.chars() {
            common_letters.insert(ch, weight);
            weight -= 1;
        }

        Self {
            hex: encoding::hex::Hex::new(),
            b64: encoding::base64::Base64::new(),
            ascii_digits,
            common_letters,
        }
    }

    // Tries to crack a hex encoded string by assuming a
    // single character key. If a solution was possible
    // it returns the message with the highest score, i.e
    // the message with the highest frequency of letters
    // a-z and A-Z.
    pub fn crack_single_char_xor(&self, input_hex: &str) -> Option<String> {
        let input_plain_bytes: Vec<u8> = match self.hex.decode(input_hex) {
            Ok(b) => b,
            Err(_) => return None, // No solution possible
        };

        let mut results = Vec::new();
        for ascii in &self.ascii_digits {
            let xor = xor_with(&input_plain_bytes, ascii.to_owned());
            match String::from_utf8(xor) {
                Ok(s) => results.push(s),
                Err(_) => {}
            }
        }

        match self.max_letter_score(&results) {
            Some(s) => Some(s.to_owned()),
            None => None,
        }
    }

    fn find_key(&self, input: &Vec<u8>) -> Option<u8> {
        let mut max = 0;
        let mut key: Option<u8> = None;

        for ascii in &self.ascii_digits {
            let xor = xor_with(input, ascii.to_owned());
            if let Ok(s) = String::from_utf8(xor) {
                let s = self.letter_score(&s);
                if s > max {
                    max = s;
                    key = Some(ascii.to_owned());
                }
            }
        }

        key
    }

    // Calculates a score based on letters (a-z, A-Z) in s.
    pub fn letter_score(&self, s: &str) -> usize {
        let mut total = 0;
        for ch in s.chars() {
            if let Some(n) = self.common_letters.get(&ch) {
                total += n
            }
        }
        total
    }

    pub fn max_letter_score<'a>(&self, v: &'a Vec<String>) -> Option<&'a String> {
        let mut found: Option<&'a String> = None;

        let mut max_score = 0;
        for r in v {
            let s = self.letter_score(r);
            if s > max_score {
                found = Some(r);
                max_score = s;
            }
        }

        found
    }

    /// Encodes `message` using `key` with repeating-key XOR.
    pub fn repeating_key_xor(&self, message: &[u8], key: &[u8]) -> Result<Vec<u8>> {
        let mut k = key.iter().cycle();

        let mut bytes: Vec<u8> = Vec::new();
        for b in message {
            let n = b ^ k.next().unwrap();
            bytes.push(n);
        }

        Ok(bytes)
    }

    /// Tries to break a repeating-key xor cipher according to: https://cryptopals.com/sets/1/challenges/6
    /// Returns Ok(message, key) if it was possible to find a key.
    ///
    /// If the key was correct, the encrypted message should be possible to
    /// break with `repeating-key-xor(message, key)`.
    pub fn break_repeating_key_xor(&self, message: &str) -> Result<(String, String)> {
        // 29 is the correct key size
        let key_size = match find_key_size(message) {
            Some(k) => k,
            None => return Err(Error::DataError(format!("failed to find any key size"))),
        };

        // 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
        // 6. Now transpose the blocks: make a block that is the first byte of every block,
        //    and a block that is the second byte of every block, and so on.
        let blocks = transponse(message, key_size);

        // 7. Solve each block as if it was single-character XOR.
        let keys: Vec<u8> = blocks
            .iter()
            .filter_map(|block| self.find_key(block))
            .collect();

        let key = from_utf8(&keys)?;
        let a = self.repeating_key_xor(message.as_bytes(), key.as_bytes())?;
        Ok((from_utf8(&a)?.to_string(), key.to_string()))
    }
}

fn find_key_size(message: &str) -> Option<usize> {
    let mut distances: Vec<(usize, f32)> = Vec::new();

    for size in 2..=40 {
        let mut text = message;
        let mut v = Vec::new();

        while text.len() > size * 2 {
            let first = &text[0..size];
            let second = &text[size..(2 * size)];

            // Normalized distance
            let d = (hamming_dist(first, second) as f32) / (size as f32);
            v.push(d);

            text = &text[(2 * size)..];
        }

        let mean: f32 = v.iter().sum::<f32>() / v.len() as f32;
        distances.push((size, mean));
    }

    distances.sort_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap());

    match distances.get(0) {
        Some((k, _)) => Some(*k),
        None => return None,
    }
}

fn transponse(message: &str, size: usize) -> Vec<Vec<u8>> {
    // Break the message into blocks of `size` length.
    let chunks: Vec<Vec<u8>> = message
        .chars()
        .collect::<Vec<char>>()
        .chunks(size)
        .map(|c| c.iter().collect::<String>().bytes().collect::<Vec<u8>>())
        .collect();

    // Make a block that is the first byte of every block,
    // and a block that is the second byte of every block, and so on.
    let mut map: BTreeMap<usize, Vec<u8>> = BTreeMap::new();
    for n in 0..size {
        for v in &chunks {
            if let Some(b) = v.get(n) {
                match map.get_mut(&n) {
                    Some(v) => v.push(*b),
                    None => {
                        let v = vec![*b];
                        map.insert(n, v);
                    }
                }
            }
        }
    }

    map.into_iter().map(|(_, v)| v).collect()
}
