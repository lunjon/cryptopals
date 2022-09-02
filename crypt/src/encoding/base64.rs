use super::{Decoder, Encoder};
use crate::{Error, Result};
use std::collections::HashMap;

const B64_CHARS: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*
Based on: https://en.m.wikibooks.org/wiki/Algorithm_Implementation/Miscellaneous/Base64
*/

pub struct Base64 {
    b_to_c: HashMap<u8, char>,
    c_to_b: HashMap<char, u8>,
}

impl Base64 {
    pub fn new() -> Self {
        let mut b_to_c: HashMap<u8, char> = HashMap::new();
        let mut c_to_b: HashMap<char, u8> = HashMap::new();
        for (ii, ch) in B64_CHARS.chars().enumerate() {
            b_to_c.insert(ii as u8, ch);
            c_to_b.insert(ch, ii as u8);
        }
        Self { b_to_c, c_to_b }
    }
}

impl Encoder for Base64 {
    fn encode(&self, src: &[u8]) -> Result<String> {
        let mut v = src.to_vec();
        let padding = match src.len() % 3 {
            1 => {
                v.push(0);
                v.push(0);
                String::from("==")
            }
            2 => {
                v.push(0);
                String::from("=")
            }
            _ => String::new(),
        };

        let mut bytes = Vec::new();
        let mut i = 0;
        let mut target = v.iter();

        while i < v.len() {
            let a = *target.next().unwrap() as u32;
            let b = *target.next().unwrap() as u32;
            let c = *target.next().unwrap() as u32;

            let n = (a << 16) + (b << 8) + (c);

            let n1 = (n >> 18 & 63) as u8;
            let n2 = (n >> 12 & 63) as u8;
            let n3 = (n >> 6 & 63) as u8;
            let n4 = (n & 63) as u8;

            for b in [n1, n2, n3, n4] {
                bytes.push(self.b_to_c.get(&b).unwrap().to_owned());
            }
            i += 3;
        }

        let result: String = bytes.iter().collect();
        let mut result = String::from(result.get(..result.len() - padding.len()).unwrap());
        result.push_str(&padding);

        Ok(result)
    }
}

impl Decoder for Base64 {
    fn decode(&self, src: &str) -> Result<Vec<u8>> {
        if src.len() % 4 != 0 {
            return Err(Error::ArgError("invalid length".to_string()));
        }

        let (s, padding) = match src.split_once("=") {
            None => (src.to_owned(), 0),
            Some((left, right)) => {
                let padding = right.to_owned() + "=";
                let fill = "A".repeat(padding.len());
                (left.to_owned() + &fill, fill.len())
            }
        };

        let lookup = |ch: &char| -> Result<u32> {
            match self.c_to_b.get(ch) {
                Some(b) => Ok(u32::from(*b)),
                None => Err(Error::DataError(format!("unknown base64 char: {}", ch))),
            }
        };

        let mut bytes = Vec::new();
        let mut i = 0;
        let mut target = s.chars();

        while i < src.len() {
            let a = lookup(&target.next().unwrap())?;
            let b = lookup(&target.next().unwrap())?;
            let c = lookup(&target.next().unwrap())?;
            let d = lookup(&target.next().unwrap())?;

            let n = (a << 18) + (b << 12) + (c << 6) + (d);

            let n1 = (n >> 16 & 255) as u8;
            let n2 = (n >> 8 & 255) as u8;
            let n3 = (n & 255) as u8;

            bytes.push(n1);
            bytes.push(n2);
            bytes.push(n3);
            i += 4;
        }

        Ok(bytes.get(0..(bytes.len() - padding)).unwrap().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::from_utf8;

    #[test]
    fn test_encode_ok() {
        let b64 = Base64::new();
        let strings = vec![
            ("Man", "TWFu"),
            (r#"{"test":true}"#, "eyJ0ZXN0Ijp0cnVlfQ=="),
        ];

        for (s, expected) in strings {
            let actual = b64.encode(s.as_bytes()).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_decode_ok() {
        let b64 = Base64::new();
        let strings = vec![
            ("TWFu", "Man"),
            ("eyJ0ZXN0Ijp0cnVlfQ==", r#"{"test":true}"#),
        ];

        for (s, expected) in strings {
            let actual = b64.decode(s).unwrap();
            let actual = from_utf8(&actual).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    #[should_panic]
    fn test_decode_error() {
        let b64 = Base64::new();
        b64.decode("lol").unwrap();
    }
}
