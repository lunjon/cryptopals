use core::pad::pkcs7;

#[test]
fn challenge_9() {
    let before = b"YELLOW SUBMARINE";
    let expected = b"YELLOW SUBMARINE\x04\x04\x04\x04";
    let actual = pkcs7(before, 20);
    assert_eq!(actual, expected);
}
