use crate::bytes::*;
use crate::crypt::*;
use rand::{thread_rng, Rng};
use std::fs;

/// # Byte-at-a-time ECB decryption (Harder)
///
/// [Set 2 / Challenge 14](https://cryptopals.com/sets/2/challenges/14)
///
/// Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:
///
/// ```
/// AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
/// ```
///
/// Same goal: decrypt the target-bytes.
///
/// ## Stop and think for a second.
///
/// What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.
///
/// Think "STIMULUS" and "RESPONSE".
pub fn solve() -> String {
  // 1. Find block size
  let block_size = find_block_size();

  // 2. Detect ECB
  let ct = encryption_oracle(&vec![0u8; 3 * block_size]);
  assert_eq!(has_repeated_block(&ct, block_size).0, true, "Is ECB");

  // 3 - 6. Decrypt

  // Find prefix length
  let prefix_length = find_prefix_length(block_size);
  let prefix_buffer = (block_size - prefix_length % block_size) % block_size;
  let prefix_blocks = (prefix_length + prefix_buffer) / block_size;

  // Initialize empty secret with correct length (with padding)
  let mut secret = vec![0u8; encryption_oracle(b"").len() - prefix_length];

  // Put the first unknown byte of the secret at the
  // end of a block to get a target for the block, then loop through all
  // characters to find the match
  for i in 0..secret.len() {
    // Cycle and offset from block_size - 1 to 0 so we can position the
    // first byte of the secret at the end of the block
    let offset_length = prefix_buffer + block_size - 1 - i % block_size;
    let offset = vec![0u8; offset_length];

    // Block we want to discover the last byte of
    let block = prefix_blocks + i / block_size;

    // Target we need to match
    let target = encryption_oracle(&offset)[block * block_size..(block + 1) * block_size].to_vec();

    // Look for the first unknown byte, placed at the last place in a block
    for c in 0..=255 {
      let pt = [&offset, &secret[..i], &[c]].concat();
      let block = (prefix_length + offset_length + i) / block_size;
      let guess = encryption_oracle(&pt)[block * block_size..(block + 1) * block_size].to_vec();
      if target == guess {
        // We have found a byte. If it was 1, then we found padding so keep to 0
        secret[i] = if c > 1 { c } else { 0 }
      }
    }
  }

  secret.retain(|&byte| byte > 0);
  secret.as_string()
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

fn has_repeated_block(ct: &[u8], block_size: usize) -> (bool, usize) {
  for window in ct
    .chunks(block_size)
    .enumerate()
    .collect::<Vec<_>>()
    .windows(2)
  {
    match window {
      [(i, a), (_, b)] => {
        if a == b {
          return (true, *i);
        }
      }
      _ => panic!("Window expected two items"),
    }
  }
  (false, 0)
}

fn find_prefix_length(block_size: usize) -> usize {
  for i in 2 * block_size..3 * block_size {
    let (has_repeat, pos) = has_repeated_block(&encryption_oracle(&vec![0; i]), block_size);
    if has_repeat {
      return (pos + 2) * block_size - i;
    }
  }
  panic!("Failed to find prefix length");
}

lazy_static! {
  static ref SECRET: Vec<u8> = fs::read_to_string("data/12.txt")
    .expect("Can't load ct")
    .replace("\n", "")
    .from_base64();
  static ref KEY: Vec<u8> = random_bytes(16);
  static ref PREFIX: Vec<u8> = random_bytes(thread_rng().gen_range(0..=100));
}

fn encryption_oracle(chosen_pt: &[u8]) -> Vec<u8> {
  let pt: Vec<u8> = [&PREFIX, chosen_pt, &SECRET].concat();
  encrypt_ecb(&KEY, &pt)
}
