use super::{arg_err, Result};

/// Calculate XOR between two slices, they must have
/// equal lengths.
pub fn xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    if a.len() != b.len() {
        arg_err!("slices must have equal length");
    }

    let mut result = Vec::new();
    let mut i = 0;
    while i < a.len() {
        let x = a[i];
        let y = b[i];
        result.push(x ^ y);
        i += 1;
    }

    Ok(result)
}

/// XOR the values in `a` with `n`.
pub fn xor_with(a: &[u8], n: u8) -> Vec<u8> {
    a.iter().map(|x| x ^ n).collect()
}

pub fn hamming_dist(a: &str, b: &str) -> usize {
    let mut count = 0;
    for (x, y) in a.bytes().zip(b.bytes()) {
        let r = x ^ y;
        count += format!("{:b}", r).chars().filter(|c| *c == '1').count();
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(37, hamming_dist("this is a test", "wokka wokka!!!"));
    }
}
