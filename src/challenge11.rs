use crate::bytes::*;
use crate::crypt::*;

use rand::{thread_rng, Rng};

/// # An ECB/CBC detection oracle
///
/// [Set 2 / Challenge 11](https://cryptopals.com/sets/2/challenges/11)
///
/// Now that you have ECB and CBC working:
///
/// Write a function to generate a random AES key; that's just 16 random bytes.
///
/// Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.
///
/// The function should look like:
///
/// ```
/// encryption_oracle(your-input)
/// => [MEANINGLESS JIBBER JABBER]
/// ```
///
/// Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
///
/// Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
///
/// Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
pub fn solve() -> String {
  let chosen_pt = &vec![0u8; 48][..];
  for _ in 0..100 {
    let (ct, is_ecb) = encryption_oracle(chosen_pt);
    let like_ecb = ct[16..32] == ct[32..48];
    assert_eq!(is_ecb, like_ecb, "Guess correctly");
  }

  String::from("done")
}

fn encryption_oracle(chosen_pt: &[u8]) -> (Vec<u8>, bool) {
  let mut rng = thread_rng();
  let key = random_bytes(16);
  let is_ecb = rng.gen();

  let prefix = random_bytes(rng.gen_range(5..=10));
  let suffix = random_bytes(rng.gen_range(5..=10));
  let pt: Vec<u8> = [&prefix, chosen_pt, &suffix].concat();

  if is_ecb {
    (encrypt_ecb(&key, &pt), is_ecb)
  } else {
    let iv = random_bytes(16);
    (encrypt_cbc(&key, &iv, &pt), is_ecb)
  }
}
