use crate::bytes::*;
use crate::crypt::*;

use std::fs;

/// # Break "random access read/write" AES CTR
///
/// [Set 4 / Challenge 25](https://cryptopals.com/sets/4/challenges/25)
///
/// Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).
///
/// Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".
///
/// Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".
///
/// Recover the original plaintext.
pub fn solve() -> String {
  // Get the plain text
  let pt = decrypt_ecb(
    b"YELLOW SUBMARINE",
    &fs::read_to_string("data/25.txt")
      .expect("Failed to open file")
      .replace("\n", "")
      .from_base64(),
  )
  .expect("can decrypt");

  // Encrypt with random key
  let ct = encrypt_ctr(&KEY, &NONCE, &pt);

  // Clone the ct and edit it with all 1s
  let mut clone = ct.clone();
  edit(&mut clone, 0, &vec![255u8; ct.len()]);
  let pad = not(&clone);

  // Decrypt by xor with the inverse
  let decrypted = xor(&ct, &pad);

  assert_eq!(pt, decrypted);

  String::from("yay")
}

lazy_static! {
  static ref KEY: Vec<u8> = random_bytes(16);
  static ref NONCE: [u8; 8] = {
    let mut nonce = [0u8; 8];
    for (i, &b) in random_bytes(8).iter().enumerate() {
      nonce[i] = b;
    }
    nonce
  };
}

// This is really sloppy :/
fn edit(ct: &mut [u8], offset: usize, pt: &[u8]) {
  let cipher = aes128(&KEY);
  for (count, block) in pt.chunks(16).enumerate() {
    let pad = &encrypt_block(&cipher, &[*NONCE, (offset + count).to_le_bytes()].concat());
    for (i, &ct_byte) in xor(&pad, block).iter().enumerate() {
      ct[(offset + count) * 16 + i] = ct_byte;
    }
  }
}
