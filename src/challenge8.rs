use crate::bytes::*;
use std::collections::HashSet;
use std::fs::File;
use std::io::{BufRead, BufReader};

/// # Detect AES in ECB mode
///
/// [Set 1 / Challenge 8](https://cryptopals.com/sets/1/challenges/8)
///
/// [In this file](https://cryptopals.com/static/challenge-data/8.txt) are a bunch of hex-encoded ciphertexts.
///
/// One of them has been encrypted with ECB.
///
/// Detect it.
///
/// Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
pub fn solve() -> String {
  let file = File::open("data/8.txt").expect("Failed to open file");
  BufReader::new(file)
    .lines()
    .map(|line| line.unwrap())
    .find(|line| has_repeats(&line.from_hex()))
    .expect("Nothing found with repeats")
}

fn has_repeats(bytes: &[u8]) -> bool {
  let mut blocks: HashSet<&[u8]> = HashSet::new();
  bytes.chunks(16).any(|block| !blocks.insert(block))
}
