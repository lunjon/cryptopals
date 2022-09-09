use crate::{Error::*, Result};

pub fn pkcs7(b: &[u8], size: usize) -> Vec<u8> {
    let mut v = b.to_vec();
    let n = b.len() % size;
    if n != 0 {
        let left = size - n;
        v.extend(vec![left as u8; left]);
    }
    v
}

/// Validate the block has valid PKSC#7 padding.
/// If so, the data is returned without the padding.
pub fn pkcs7_validate<'a>(block: &'a str, size: usize) -> Result<&'a str> {
    if block.len() == 0 || size == 0 {
        return Err(DataError("empty block or size".to_string()));
    } else if block.len() != size {
        return Err(DataError(format!(
            "invalid size of data: expected {} but was {}",
            size,
            block.len()
        )));
    }

    let last_char = block.chars().last().unwrap();
    let ran = '\x01'..'\x0f';
    if !ran.contains(&last_char) {
        return Ok(block);
    }

    let mut bytes = block.as_bytes().to_vec();
    bytes.reverse();

    let last_byte = &bytes[0];
    let count = bytes.iter().filter(|b| *b == last_byte).count();

    if *last_byte as usize == count {
        let index = block.len() - count as usize;
        Ok(&block[0..index])
    } else {
        Err(DataError("invalid padding".to_string()))
    }
}

pub fn pkcs7_inplace(b: &mut Vec<u8>, size: usize) {
    let n = b.len() % size;
    if n != 0 {
        let left = size - n;
        b.extend(vec![left as u8; left]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkcs7() {
        let before = b"test";
        let expected = b"test\x04\x04\x04\x04";
        let actual = pkcs7(before, 8);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_pkcs7_nopad() {
        let before = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE";
        let actual = pkcs7(before, 16);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_pkcs7_validate() {
        let tests = [
            ("test", "test\x04\x04\x04\x04"),
            ("testtest", "testtest"),
            ("test!", "test!\x03\x03\x03"),
        ];
        for (expected, padded) in tests {
            let actual = pkcs7_validate(padded, 8).unwrap();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn test_pkcs7_validate_invalid_padding() {
        let tests = ["test\x01", "test\x04\x04\x04", "test\x04\x04\x04"];
        for t in tests {
            let res = pkcs7_validate(t, 8);
            assert!(res.is_err());
        }
    }

    #[test]
    fn test_pkcs7_validate_invalid_params() {
        let tests = [("", 0), ("test", 8)];
        for (block, size) in tests {
            let res = pkcs7_validate(block, size);
            assert!(res.is_err());
        }
    }
}
