use super::{Decoder, Encoder};
use crate::{Error, Result};
use std::collections::HashMap;

const HEX_CHARS: &str = "0123456789abcdef";

pub struct Hex {
    b_to_c: HashMap<u8, char>,
    c_to_b: HashMap<char, u8>,
}

impl Hex {
    pub fn new() -> Self {
        let mut b_to_c: HashMap<u8, char> = HashMap::new();
        let mut c_to_b: HashMap<char, u8> = HashMap::new();
        for (ii, ch) in HEX_CHARS.chars().enumerate() {
            b_to_c.insert(ii as u8, ch);
            c_to_b.insert(ch, ii as u8);
        }

        Self { b_to_c, c_to_b }
    }
}

impl Encoder for Hex {
    fn encode(&self, src: &[u8]) -> Result<String> {
        let mut encoded = Vec::new();

        for b in src {
            let n1 = b >> 4;
            let n2 = b & 0b0001111;
            encoded.push(self.b_to_c.get(&n1).unwrap().to_owned());
            encoded.push(self.b_to_c.get(&n2).unwrap().to_owned());
        }

        Ok(encoded.iter().collect())
    }
}

impl Decoder for Hex {
    fn decode(&self, src: &str) -> Result<Vec<u8>> {
        if src.len() % 2 != 0 {
            return Err(Error::DataError(String::from("length not multiple of 2")));
        }

        let mut decoded = Vec::new();
        let mut index = 0;
        let mut bytes = src.chars();

        while index < src.len() {
            let a = bytes.next().unwrap();
            let a = self.c_to_b.get(&a).unwrap();
            let a = a << 4;

            let b = bytes.next().unwrap();
            let b = self.c_to_b.get(&b).unwrap();
            let b = b & 0b00001111;

            decoded.push(a + b);
            index += 2;
        }

        Ok(decoded)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::from_utf8;

    #[test]
    fn test_encode_ok() {
        let hex = Hex::new();
        let strings = vec![("Hello", "48656c6c6f")];

        for (s, expected) in strings {
            let actual = hex.encode(s.as_bytes()).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_decode_ok() {
        let hex = Hex::new();
        let strings = vec![
            ("48656c6c6f", "Hello"),
            ("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", "I'm killing your brain like a poisonous mushroom")
        ];

        for (s, expected) in strings {
            let actual = hex.decode(s).unwrap();
            let actual = from_utf8(&actual).unwrap();
            assert_eq!(actual, expected);
        }
    }
}
