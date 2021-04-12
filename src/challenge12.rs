use crate::bytes::*;
use crate::crypt::*;
use std::fs;

/// # Byte-at-a-time ECB decryption (Simple)
///
/// [Set 2 / Challenge 12](https://cryptopals.com/sets/2/challenges/12)
///
/// Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).
///
/// Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:
///
/// ```
/// Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
/// aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
/// dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
/// YnkK
/// ```
///
/// Do not decode this string now. Don't do it.
///
/// Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.
///
/// What you have now is a function that produces:
///
/// ```
/// AES-128-ECB(your-string || unknown-string, random-key)
/// ```
///
/// It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
///
/// Here's roughly how:
///
/// 1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
/// 2. Detect that the function is using ECB. You already know, but do this step anyways.
/// 3. Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
/// 4. Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
/// 5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
/// 6. Repeat for the next byte.
/// Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
///
/// Congratulations.
/// This is the first challenge we've given you whose solution will break real crypto. Lots of people know that when you encrypt something in ECB mode, you can see penguins through it. Not so many of them can decrypt the contents of those ciphertexts, and now you can. If our experience is any guideline, this attack will get you code execution in security tests about once a year.
pub async fn solve(solution: &str) {
  // 1. Find block size
  let block_size = find_block_size();

  // 2. Detect ECB
  let ct = encryption_oracle(&vec![0u8; 2 * block_size]);
  assert_eq!(ct[..block_size], ct[block_size..2 * block_size], "Is ECB");

  // 3 - 6. Decrypt

  // Initialize empty secret with correct length (with padding)
  let mut secret = vec![0u8; encryption_oracle(b"").len()];

  // Put the first unknown byte of the secret at the
  // end of a block to get a target for the block, then loop through all
  // characters to find the match
  for i in 0..secret.len() {
    // Cycle and offset from block_size - 1 to 0 so we can position the
    // first byte of the secret at the end of the block
    let offset_length = block_size - i % block_size - 1;
    let offset = vec![0u8; offset_length];

    // Block we want to discover the last byte of
    let block = i / block_size;

    // Target we need to match
    let target = encryption_oracle(&offset)[block * block_size..(block + 1) * block_size].to_vec();

    // Look for the first unknown byte, placed at the last place in a block
    for c in 0..=255 {
      let pt = [&offset, &secret[..i], &[c]].concat();
      let block = (offset_length + i) / block_size;
      let guess = encryption_oracle(&pt)[block * block_size..(block + 1) * block_size].to_vec();
      if target == guess {
        // We have found a byte. If it was 1, then we found padding so keep to 0
        secret[i] = if c > 1 { c } else { 0 }
      }
    }
  }

  secret.retain(|&byte| byte > 0);
  assert_eq!(secret.as_string(), solution);
}

fn find_block_size() -> usize {
  let mut pt = Vec::new();
  let base_length = encryption_oracle(&pt).len();

  // Find jump in length
  loop {
    pt.push(0);
    let length = encryption_oracle(&pt).len();
    if length != base_length {
      return length - base_length;
    }
  }
}

lazy_static! {
  static ref SECRET: Vec<u8> = fs::read_to_string("data/12.txt")
    .expect("Can't load ct")
    .replace("\n", "")
    .from_base64();
  static ref KEY: Vec<u8> = random_bytes(16);
}

fn encryption_oracle(chosen_pt: &[u8]) -> Vec<u8> {
  let pt: Vec<u8> = [chosen_pt, &SECRET].concat();
  encrypt_ecb(&KEY, &pt)
}
