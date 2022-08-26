use super::Result;

pub mod base64;
pub mod hex;

pub trait Encoder {
    fn encode(&self, b: &[u8]) -> Result<String>;
}

pub trait Decoder {
    fn decode(&self, b: &str) -> Result<Vec<u8>>;
}
