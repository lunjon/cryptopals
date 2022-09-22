use clap::{app_from_crate, App, AppSettings, Arg, ArgMatches};
use crypt::aes::{decrypt_128, encrypt_128, Mode};
use crypt::encoding::{base64::Base64, hex::Hex, Decoder, Encoder};
use crypt::util;
use crypt::{Error, Hacker, Result};
use openssl::hash::{self, MessageDigest};
use std::str::from_utf8;

const IN_ARG_NAME: &str = "in";
const OUT_ARG_NAME: &str = "out";

pub struct Cli {
    hex: Hex,
    b64: Base64,
    hacker: Hacker,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            hex: Hex::new(),
            b64: Base64::new(),
            hacker: Hacker::new(),
        }
    }
}

impl Cli {
    pub fn exec(&self) -> Result<()> {
        let matches = app_from_crate!()
            .global_setting(AppSettings::PropagateVersion)
            .global_setting(AppSettings::UseLongFormatForHelpSubcommand)
            .setting(AppSettings::SubcommandRequiredElseHelp)
            .subcommand(
                App::new("encrypt")
                    .about("Encrypt into a ciphertext.")
                    .arg(
                        Arg::new("key")
                            .help("Hex encoded string to use as key.")
                            .long("key")
                            .short('k')
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(IN_ARG_NAME)
                            .long(IN_ARG_NAME)
                            .help("Read input from files, else use stdin.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(OUT_ARG_NAME)
                            .long(OUT_ARG_NAME)
                            .help("Write result to file, else use stdout.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("iv")
                            .help("Initialization vector used by modes that requires it.")
                            .long("iv")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("method")
                            .help("Encryption method to use.")
                            .long("method")
                            .short('m')
                            .possible_values(["repeating-key-xor", "rkx", "aes-cbc", "aes-ecb"])
                            .required(true),
                    ),
            )
            .subcommand(
                App::new("decrypt")
                    .about("Decrypt a ciphertext.")
                    .arg(
                        Arg::new("key")
                            .help("Hex encoded string to use as key.")
                            .long("key")
                            .short('k')
                            .required(true)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(IN_ARG_NAME)
                            .long(IN_ARG_NAME)
                            .help("Read input from files, else use stdin.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(OUT_ARG_NAME)
                            .long(OUT_ARG_NAME)
                            .help("Write result to file, else use stdout.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("iv")
                            .help("Initialization vector used by modes that requires it.")
                            .long("iv")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("method")
                            .help("Decryption method to use.")
                            .long("method")
                            .short('m')
                            .possible_values(["repeating-key-xor", "rkx", "aes-cbc", "aes-ecb"])
                            .required(true),
                    ),
            )
            .subcommand(
                App::new("encode")
                    .about("Encodes text to a given scheme.")
                    .arg(
                        Arg::new(IN_ARG_NAME)
                            .help("Read input from files, else use stdin.")
                            .long(IN_ARG_NAME)
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(OUT_ARG_NAME)
                            .long(OUT_ARG_NAME)
                            .help("Write result to file, else use stdout.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("scheme")
                            .long("scheme")
                            .short('s')
                            .possible_values(["hex", "b64", "base64"])
                            .required(true),
                    ),
            )
            .subcommand(
                App::new("decode")
                    .about("Decodes text from a given scheme.")
                    .arg(
                        Arg::new(IN_ARG_NAME)
                            .long(IN_ARG_NAME)
                            .help("Read input from files, else use stdin.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(OUT_ARG_NAME)
                            .long(OUT_ARG_NAME)
                            .help("Write result to file.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new("scheme")
                            .long("scheme")
                            .short('s')
                            .possible_values(["hex", "b64", "base64"])
                            .required(true),
                    ),
            )
            .subcommand(
                App::new("hash")
                    .about("Hash functions.")
                    .arg(
                        Arg::new("digest")
                            .long("digest")
                            .short('d')
                            .help("Message digest kind.")
                            .required(true)
                            .possible_values(&["md5", "sha256", "sha512", "sha3_256", "shake_256"]),
                    )
                    .arg(
                        Arg::new(IN_ARG_NAME)
                            .long(IN_ARG_NAME)
                            .help("Read input from file, else use stdin.")
                            .takes_value(true),
                    )
                    .arg(
                        Arg::new(OUT_ARG_NAME)
                            .long(OUT_ARG_NAME)
                            .help("Write result to file.")
                            .takes_value(true),
                    ),
            )
            .get_matches();

        match matches.subcommand() {
            Some(("encrypt", sub_matches)) => self.handle_encrypt(sub_matches),
            Some(("decrypt", sub_matches)) => self.handle_decrypt(sub_matches),
            Some(("encode", sub_matches)) => self.handle_encode(sub_matches),
            Some(("decode", sub_matches)) => self.handle_decode(sub_matches),
            Some(("hash", sub_matches)) => self.handle_hash(sub_matches),
            _ => unreachable!(),
        }
    }
}

// encrypt/decrypt
impl Cli {
    fn handle_encrypt(&self, matches: &ArgMatches) -> Result<()> {
        let buffer = get_input(matches.value_of(IN_ARG_NAME))?;
        let key_hex = matches.value_of("key").unwrap().trim();
        let key = self.hex.decode(key_hex)?;

        let encrypted = match matches.value_of("method").unwrap() {
            "rkx" | "repeating-key-xor" => self.hacker.repeating_key_xor(&buffer, &key)?,
            "aes-ecb" => encrypt_128(Mode::ECB, &buffer, &key)?,
            "aes-cbc" => {
                let iv = self.get_iv(matches.value_of("iv"))?;
                encrypt_128(Mode::CBC(iv), &buffer, &key)?
            }
            _ => unreachable!(),
        };

        write_output(matches.value_of(OUT_ARG_NAME), &encrypted)
    }

    fn handle_decrypt(&self, matches: &ArgMatches) -> Result<()> {
        let buffer = get_input(matches.value_of(IN_ARG_NAME))?;
        let key_hex = matches.value_of("key").unwrap().trim();
        let key = self.hex.decode(key_hex)?;

        let decrypted = match matches.value_of("method").unwrap() {
            "rkx" | "repeating-key-xor" => self.hacker.repeating_key_xor(&buffer, &key)?,
            "aes-ecb" => decrypt_128(Mode::ECB, &buffer, &key)?,
            "aes-cbc" => {
                let iv = self.get_iv(matches.value_of("iv"))?;
                decrypt_128(Mode::CBC(iv), &buffer, &key)?
            }
            _ => unreachable!(),
        };

        write_output(matches.value_of(OUT_ARG_NAME), &decrypted)
    }
}

// encode/decode
impl Cli {
    fn handle_encode(&self, matches: &ArgMatches) -> Result<()> {
        let buffer = get_input(matches.value_of(IN_ARG_NAME))?;

        let s = match matches.value_of("scheme").unwrap() {
            "hex" => self.hex.encode(&buffer)?,
            "b64" | "base64" => self.b64.encode(&buffer)?,
            _ => unreachable!(),
        };

        match matches.value_of(OUT_ARG_NAME) {
            None => println!("{}", s),
            Some(f) => util::write_bytes(f, s.as_bytes())?,
        }

        Ok(())
    }

    fn handle_decode(&self, matches: &ArgMatches) -> Result<()> {
        let buffer = get_input(matches.value_of(IN_ARG_NAME))?;
        let s = from_utf8(&buffer)?.trim(); // The string includes a newline character at the end.

        let v = match matches.value_of("scheme").unwrap() {
            "hex" => self.hex.decode(s)?,
            "b64" | "base64" => self.b64.decode(s)?,
            _ => unreachable!(),
        };
        write_output(matches.value_of(OUT_ARG_NAME), &v)
    }

    fn get_iv(&self, iv: Option<&str>) -> Result<Vec<u8>> {
        match iv {
            Some(s) => self.hex.decode(s),
            None => Err(Error::ArgError(
                "CBC mode requires the --iv option".to_string(),
            )),
        }
    }
}

impl Cli {
    fn handle_hash(&self, matches: &ArgMatches) -> Result<()> {
        let buffer = get_input(matches.value_of(IN_ARG_NAME))?;
        let digest = match matches.value_of("digest").unwrap() {
            "md5" => MessageDigest::md5(),
            "sha256" => MessageDigest::sha256(),
            "sha512" => MessageDigest::sha512(),
            "sha3_256" => MessageDigest::sha3_256(),
            "shake_256" => MessageDigest::shake_256(),
            _ => unreachable!(),
        };

        let res = hash::hash(digest, &buffer)?;
        let hex = self.hex.encode(&res)?;
        write_output(matches.value_of(OUT_ARG_NAME), hex.as_bytes())
    }
}

fn get_input(file: Option<&str>) -> Result<Vec<u8>> {
    match file {
        Some(f) => util::read_bytes(f),
        None => util::read_stdin(),
    }
}

fn write_output(out: Option<&str>, data: &[u8]) -> Result<()> {
    match out {
        Some(outfile) => util::write_bytes(outfile, data),
        None => util::write_stdout(data),
    }
}
