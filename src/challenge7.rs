use crate::bytes::*;
use crate::crypt::*;
use std::fs;

/// # AES in ECB mode
///
/// [Set 1 / Challenge 7](https://cryptopals.com/sets/1/challenges/7)
///
/// The Base64-encoded content in [this file](https://cryptopals.com/static/challenge-data/7.txt) has been encrypted via AES-128 in ECB mode under the key
///
/// ```
/// "YELLOW SUBMARINE".
/// ```
///
/// (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
///
/// Decrypt it. You know the key, after all.
///
/// Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.
///
/// Do this with code.
///
/// You can obviously decrypt this using the OpenSSL command-line tool, but we're having you get ECB working in code for a reason. You'll need it a lot later on, and not just for attacking ECB..
pub async fn solve(solution: &str) {
  let key = b"YELLOW SUBMARINE";
  let ct = fs::read_to_string("data/7.txt")
    .expect("Can't load ct")
    .replace("\n", "")
    .from_base64();

  assert_eq!(
    decrypt_ecb(key, &ct)
      .expect("Expected correct padding")
      .as_string(),
    solution
  );
}
