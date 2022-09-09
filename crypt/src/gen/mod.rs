use rand::{Rng, RngCore};
use std::ops::Range;

pub fn random_key() -> Vec<u8> {
    let mut data = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut data);
    data.to_vec()
}

pub fn random_data(r: Range<usize>) -> Vec<u8> {
    let mut data = Vec::new();
    let mut rng = rand::thread_rng();
    let a: usize = rng.gen_range(r);
    for _ in 0..a {
        let n: u8 = rng.gen();
        data.push(n);
    }
    data
}
