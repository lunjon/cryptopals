use super::{Error, Result};
use crate::gen::{random_data, random_key};
use crate::util;
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::random;

#[cfg(test)]
mod tests;

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

pub fn encrypt_oracle(data: &[u8]) -> Result<(Vec<u8>, bool)> {
    let key = random_key();
    let mut v: Vec<u8> = Vec::new();
    v.extend(random_data(5..11));
    v.extend(data);
    v.extend(random_data(5..11));

    if random::<bool>() {
        let b = encrypt_128(Mode::ECB, data, &key)?;
        Ok((b, true))
    } else {
        let iv = random_key();
        let b = encrypt_128(Mode::CBC(iv), data, &key)?;
        Ok((b, false))
    }
}

/// Try to detect AES mode by looking at the plaintext and encrypted data.
pub fn detection_oracle(plaintext: &[u8], encrypted: &[u8]) -> Result<String> {
    // Use the fact that ECB mode always produces the same
    // output given the same key and block.

    if plaintext.len() < BLOCK_SIZE {
        return Err(Error::DataError(format!(
            "to short data length to be able to detect mode: {}",
            plaintext.len()
        )));
    }

    let window_size = 4;
    let end_index = plaintext.len() - window_size * 2;

    for a_start in 0..end_index {
        let a_offset = a_start + window_size;
        let a = &plaintext[a_start..a_offset];

        for b_start in a_offset..plaintext.len() - window_size {
            let b_offset = b_start + window_size;
            let b = &plaintext[b_start..b_offset];

            if util::slices_equal(a, b) {
                // Check if plaintext at the same offset are equal => ECB mode
                let x = &encrypted[a_start..a_offset];
                let y = &encrypted[b_start..b_offset];
                if util::slices_equal(x, y) {
                    return Ok("ECB".to_string());
                }
            }
        }
    }
    Ok("CBC".to_string())
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

    let cipher = Cipher::aes_128_ecb();
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
