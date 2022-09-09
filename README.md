# Cryptopals

Code that tries to solves the cryptographic challenges at [cryptopals](https://cryptopals.com/).

## Projects
The repository contains three Rust crates:
 - **challenges**: Code for the actual challenges.
 - **cli**: CLI that exposes some of the functionality implemented in the challenges.
 - **crypt**: Core functionality shared between the challenges and CLI.

## Challenges

### Set 1
 0. ~Convert hex to base64~
 1. ~Fixed XOR~
 2. ~Single-byte XOR cipher~
 3. ~Detect single-character XOR~
 6. ~Implement repeating-key XOR~
 6. ~Break repeating-key XOR~
 7. ~AES in ECB mode~
 8. ~Detect AES in ECB mode~

### Set 2
 9.  ~Implement PKCS#7 padding~
 10. ~Implement CBC mode~
 11. ~An ECB/CBC detection oracle~
 12. ~Byte-at-a-time ECB decryption (Simple)~
 13. ~ECB cut-and-paste~
 14. Byte-at-a-time ECB decryption (Harder)
 15. ~PKCS#7 padding validation~
 16. CBC bitflipping attacks
