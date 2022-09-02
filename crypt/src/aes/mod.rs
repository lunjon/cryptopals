use super::{Error, Result};
use crate::util;
use openssl::symm::{decrypt, encrypt, Cipher};
use rand::{random, Rng, RngCore};
use std::ops::Range;

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

fn random_key() -> Vec<u8> {
    let mut data = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut data);
    data.to_vec()
}

fn random_data(r: Range<usize>) -> Vec<u8> {
    let mut data = Vec::new();
    let mut rng = rand::thread_rng();
    let a: usize = rng.gen_range(r);
    for _ in 0..a {
        let n: u8 = rng.gen();
        data.push(n);
    }
    data
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

/// Try to detect AES mode by looking at the encrypted data.
pub fn detection_oracle(data: &[u8]) -> Result<String> {
    // Use the fact that ECB mode always produces the same
    // output given the same key and block.
    //   => make a sweeping window of 16 bytes
    //      and try to find two equal consecutive blocks:
    //      ... [ a ] [ b ] ...
    //      if a == b => ECB.
    if data.len() < BLOCK_SIZE * 4 {
        return Err(Error::DataError(format!(
            "to short data length to be able to detect mode: {}",
            data.len()
        )));
    }

    let end_index = data.len() - BLOCK_SIZE * 2;
    for index in 0..end_index {
        let middle = index + BLOCK_SIZE;
        let end = index + BLOCK_SIZE * 2;
        let a = &data[index..middle];
        let b = &data[middle..end];

        if util::slices_equal(a, b) {
            return Ok("ECB".to_string());
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
