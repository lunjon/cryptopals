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

pub fn pkcs7_validate<'a>(b: &'a str, size: usize) -> Result<&'a str> {
    if b.len() != size {
        return Err(DataError(format!(
            "invalid size of data: expected {} but was {}",
            size,
            b.len()
        )));
    }
    todo!()
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
        let before = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
        let actual = pkcs7(before, 20);

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_pkcs7_nopad() {
        let before = b"YELLOW SUBMARINE";
        let expected = b"YELLOW SUBMARINE";
        let actual = pkcs7(before, 16);

        assert_eq!(actual, expected);
    }
}
