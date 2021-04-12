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
pub async fn solve() {
  let file = File::open("data/8.txt").expect("Failed to open file");
  assert_eq!(BufReader::new(file)
    .lines()
    .map(|line| line.unwrap())
    .find(|line| has_repeats(&line.from_hex()))
    .expect("Nothing found with repeats"),
  "d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
}

fn has_repeats(bytes: &[u8]) -> bool {
  let mut blocks: HashSet<&[u8]> = HashSet::new();
  bytes.chunks(16).any(|block| !blocks.insert(block))
}
