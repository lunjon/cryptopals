use super::{Error, Result};
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::{random, Rng, RngCore};

/// Wrapper of the openssl crate:
/// https://docs.rs/openssl/latest/openssl/index.html

const BLOCK_SIZE: usize = 16;

pub enum Mode {
    ECB,
    CBC(Vec<u8>),
}

fn check_block_len(b: &[u8]) -> Result<()> {
    if b.len() == BLOCK_SIZE {
        Ok(())
    } else {
        Err(Error::DataError(format!(
            "invalid length: must have length {} but was {}",
            BLOCK_SIZE,
            b.len()
        )))
    }
}

fn check_data_len(data: &[u8]) -> Result<()> {
    match data.len() % BLOCK_SIZE {
        0 => Ok(()),
        _ => Err(Error::DataError(format!(
            "data not multiple of {}",
            BLOCK_SIZE
        ))),
    }
}

fn random_key() -> Vec<u8> {
    let mut data = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut data);
    data.to_vec()
}

fn random_data() -> Vec<u8> {
    let mut data = Vec::new();
    let mut rng = rand::thread_rng();
    let a: usize = rng.gen_range(5..10);
    for _ in 0..a {
        let n: u8 = rng.gen();
        data.push(n);
    }
    data
}

pub fn encrypt_oracle(data: &[u8]) -> Result<Vec<u8>> {
    let key = random_key();
    let mut v: Vec<u8> = Vec::new();
    v.extend(random_data());
    v.extend(data);
    v.extend(random_data());

    if random::<bool>() {
        encrypt_128(Mode::ECB, data, &key)
    } else {
        let iv = random_key();
        encrypt_128(Mode::CBC(iv), data, &key)
    }
}

pub fn encrypt_128(mode: Mode, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    match mode {
        Mode::ECB => encrypt_128_ecb(data, key),
        Mode::CBC(iv) => encrypt_128_cbc(&iv, data, key),
    }
}

pub fn decrypt_128(mode: Mode, data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    check_block_len(key)?;

    match mode {
        Mode::ECB => decrypt_128_ecb(data, key),
        Mode::CBC(iv) => decrypt_128_cbc(&iv, data, key),
    }
}

fn encrypt_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    check_block_len(key)?;
    // check_data_len(data)?;

    // let mut results: Vec<u8> = Vec::new();

    let cipher = Cipher::aes_128_ecb();
    // for block in data.chunks(BLOCK_SIZE) {
    //     match encrypt(cipher, key, None, block) {
    //         Ok(v) => results.extend_from_slice(&v),
    //         Err(err) => return Err(Error::DataError(format!("error encrypting: {}", err))),
    //     }
    // }
    match encrypt(cipher, key, None, data) {
        Ok(v) => Ok(v),
        Err(err) => Err(Error::DataError(format!("error encrypting: {}", err))),
    }
}

fn encrypt_128_cbc(iv: &[u8], data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    check_block_len(key)?;
    check_block_len(iv)?;

    let cipher = Cipher::aes_128_cbc();
    match encrypt(cipher, key, Some(iv), data) {
        Ok(v) => Ok(v),
        Err(err) => Err(Error::DataError(format!("error encrypting: {}", err))),
    }
}

fn decrypt_128_ecb(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    check_data_len(data)?;
    check_block_len(key)?;

    let cipher = Cipher::aes_128_ecb();
    match decrypt(cipher, key, None, data) {
        Ok(v) => Ok(v),
        Err(err) => return Err(Error::DataError(format!("error decrypting: {}", err))),
    }
}

fn decrypt_128_cbc(iv: &[u8], data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    check_data_len(data)?;
    check_block_len(iv)?;
    check_block_len(key)?;

    let cipher = Cipher::aes_128_cbc();
    match decrypt(cipher, key, Some(iv), data) {
        Ok(v) => Ok(v),
        Err(err) => Err(Error::DataError(format!("error decrypting: {}", err))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"YELLOW SUBMARINE";

    #[test]
    fn test_encrypt_128_ecb() {
        let data = b"Some Crypto Text";
        let encrypted = encrypt_128(Mode::ECB, data, KEY).unwrap();
        assert!(encrypted.len() > 0);
    }

    #[test]
    fn test_encrypt_128_cbc() {
        let data = b"Some Crypto Text";

        let encrypted = encrypt_128(Mode::CBC(KEY.to_vec()), data, KEY).unwrap();
        assert!(encrypted.len() > 0);
    }

    #[test]
    fn test_encrypt_oracle() {
        let data = b"Some Crypto Text and something else";
        let encrypted = encrypt_oracle(data).unwrap();
        assert!(encrypted.len() > 0);
    }

    #[test]
    fn test_decrypt_128_ecb() {
        let data = b"Some Crypto Text";

        let encrypted = encrypt_128(Mode::ECB, data, KEY).unwrap();
        let decrypted = decrypt_128(Mode::ECB, &encrypted, KEY).unwrap();
        assert_eq!(decrypted, data);
    }

    #[test]
    fn test_decrypt_128_cbc() {
        let data = b"Some Crypto Text";

        let encrypted = encrypt_128(Mode::CBC(KEY.to_vec()), data, KEY).unwrap();
        let decrypted = decrypt_128(Mode::CBC(KEY.to_vec()), &encrypted, KEY).unwrap();
        assert_eq!(decrypted, data);
    }
}
