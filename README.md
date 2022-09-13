# Cryptopals

Code that tries to solves the cryptographic challenges at [cryptopals](https://cryptopals.com/).

## Projects
The repository contains three Rust crates:
 - **challenges**: Code for the actual challenges.
 - **cli**: CLI that exposes some of the functionality implemented in the challenges.
 - **crypt**: Core functionality shared between the challenges and CLI.

## Challenges

### Set 1
 0. [x] Convert hex to base64~
 1. [x] Fixed XOR~
 2. [x] Single-byte XOR cipher~
 3. [x] Detect single-character XOR~
 6. [x] Implement repeating-key XOR~
 6. [x] Break repeating-key XOR~
 7. [x] AES in ECB mode~
 8. [x] Detect AES in ECB mode~

### Set 2
 9.  [x] Implement PKCS#7 padding~
 10. [x] Implement CBC mode~
 11. [x] An ECB/CBC detection oracle~
 12. [x] Byte-at-a-time ECB decryption (Simple)~
 13. [x] ECB cut-and-paste~
 14. Byte-at-a-time ECB decryption (Harder)
 15. [x] PKCS#7 padding validation~
 16. CBC bitflipping attacks
