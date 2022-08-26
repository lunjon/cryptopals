use std::str::from_utf8;
use core::aes::{decrypt_128, Mode};
use core::encoding::base64::*;
use core::encoding::hex::*;
use core::encoding::*;
use core::op::xor;
use core::util::read_lines;
use core::{Hacker, Result};

#[test]
fn challenge_1() -> Result<()> {
    let b64 = Base64::new();
    let hex = Hex::new();

    let str_hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    let str_b64 = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";
    let str_plain = "I'm killing your brain like a poisonous mushroom";

    let a = hex.decode(str_hex)?;
    let a = from_utf8(&a)?;

    let b = b64.encode(a.as_bytes())?;

    assert_eq!(str_plain, a);
    assert_eq!(str_b64, b);
    Ok(())
}

#[test]
fn challenge_2() -> Result<()> {
    let coder = Hex::new();
    let a = coder.decode("1c0111001f010100061a024b53535009181c")?;
    let b = coder.decode("686974207468652062756c6c277320657965")?;

    let r = xor(&a, &b).unwrap();
    let s = coder.encode(&r)?;
    assert_eq!(
        "746865206b696420646f6e277420706c6179",
        s
    );
    Ok(())
}

#[test]
fn challenge_3() {
    let input_hex = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let hacker = Hacker::new();
    let message = hacker.crack_single_char_xor(input_hex).unwrap();
    assert_eq!("Cooking MC's like a pound of bacon", message);
}

#[test]
fn challenge_4() {
    let lines = read_lines("data/set1_challenge4.txt").unwrap();
    let hacker = Hacker::new();

    let results: Vec<String> = lines
        .iter()
        .filter_map(|line| hacker.crack_single_char_xor(line))
        .collect();

    assert!(results.len() > 0);

    let message = hacker.max_letter_score(&results).unwrap();
    assert_eq!("Now that the party is jumping\n", message);
}

#[test]
fn challenge_5() {
    let message = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";
    let hacker = Hacker::new();

    let encoded = hacker.repeating_key_xor(message.as_bytes(), key.as_bytes()).unwrap();
    let encoded_hex = hacker.hex.encode(&encoded).unwrap();

    let expected = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f";
    assert_eq!(expected, encoded_hex);
}

#[test]
fn challenge_6() -> Result<()> {
    let lines = read_lines("data/set1_challenge6.txt")?;
    let encrypted_b64 = lines.join("");
    let hacker = Hacker::new();

    let encrypted_plain = hacker.b64.decode(&encrypted_b64)?;
    let encrypted_plain = from_utf8(&encrypted_plain)?;
    let (message, key) = hacker.break_repeating_key_xor(&encrypted_plain)?;

    assert!(message.contains("Play that funky music, white boy"));
    assert_eq!(key, "Terminator X: Bring the noise");

    Ok(())
}

#[test]
fn challenge_7() -> Result<()> {
    let lines = read_lines("data/set1_challenge7.txt")?;
    let encrypted_b64 = lines.join("");
    let hacker = Hacker::new();

    let encrypted_plain = hacker.b64.decode(&encrypted_b64)?;
    let key = b"YELLOW SUBMARINE";
    let decrypted_bytes = decrypt_128(Mode::ECB, &encrypted_plain, key)?;
    let s = from_utf8(&decrypted_bytes)?;
    assert!(s.contains("Play that funky music"));

    Ok(())
}

fn has_repeats<T>(i: T) -> bool
where
    T: Iterator,
    <T as Iterator>::Item: Ord,
{
    let mut v: Vec<_> = i.collect();
    let len = v.len();
    v.sort();
    v.dedup();
    len != v.len()
}

#[test]
fn challenge_8() -> Result<()> {
    let lines = read_lines("data/set1_challenge8.txt")?;
    let hacker = Hacker::new();

    let result = lines
        .iter()
        .filter_map(|line| match hacker.hex.decode(line) {
            Ok(b) => Some(b),
            Err(_) => None,
        })
        .find(|b| has_repeats(b.chunks(16)));

    assert!(result.is_some());
    Ok(())
}
